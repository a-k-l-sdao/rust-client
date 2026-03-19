use blake2::{Blake2b, Digest};
use f1r3fly_models::casper::v1::deploy_response::Message as DeployResponseMessage;
use f1r3fly_models::casper::v1::deploy_service_client::DeployServiceClient;
use f1r3fly_models::casper::v1::exploratory_deploy_response::Message as ExploratoryDeployResponseMessage;
use f1r3fly_models::casper::v1::is_finalized_response::Message as IsFinalizedResponseMessage;
use f1r3fly_models::casper::v1::rho_data_response::Message as RhoDataResponseMessage;
use f1r3fly_models::casper::v1::propose_response::Message as ProposeResponseMessage;
use f1r3fly_models::casper::v1::propose_service_client::ProposeServiceClient;
use f1r3fly_models::casper::{
    BlocksQuery, BlocksQueryByHeight, DataAtNameByBlockQuery, DeployDataProto,
    ExploratoryDeployQuery, IsFinalizedQuery, LightBlockInfo, ProposeQuery,
};
use f1r3fly_models::rhoapi::g_unforgeable::UnfInstance;
use f1r3fly_models::rhoapi::{GDeployId, GUnforgeable, Par};
use f1r3fly_models::ByteString;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature as K256Signature, SigningKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use typenum::U32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployInfo {
    pub deploy_id: String,
    pub block_hash: Option<String>,
    pub sender: Option<String>,
    pub seq_num: Option<u64>,
    pub sig: Option<String>,
    pub sig_algorithm: Option<String>,
    pub shard_id: Option<String>,
    pub version: Option<u64>,
    pub timestamp: Option<u64>,
    pub status: DeployStatus,
    /// Whether the deploy execution errored
    pub errored: bool,
    /// System deploy error message (e.g., "Insufficient funds")
    pub system_deploy_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeployStatus {
    Pending,       // Deploy submitted but not yet in a block
    Included,      // Deploy included in a block
    NotFound,      // Deploy ID not found
    Error(String), // Error occurred
}

/// Client for interacting with the F1r3fly API
pub struct F1r3flyApi<'a> {
    signing_key: SigningKey,
    node_host: &'a str,
    grpc_port: u16,
}

impl<'a> F1r3flyApi<'a> {
    /// Creates a new F1r3fly API client
    ///
    /// # Arguments
    ///
    /// * `signing_key` - Hex-encoded private key for signing deploys
    /// * `node_host` - Hostname or IP address of the F1r3fly node
    /// * `grpc_port` - gRPC port for the node's API service
    ///
    /// # Returns
    ///
    /// A new `F1r3flyApi` instance
    pub fn new(signing_key: &str, node_host: &'a str, grpc_port: u16) -> Self {
        let key_bytes = hex::decode(signing_key).expect("Invalid hex private key");
        F1r3flyApi {
            signing_key: SigningKey::from_slice(&key_bytes).expect("Invalid private key"),
            node_host,
            grpc_port,
        }
    }

    /// Deploys Rholang code to the F1r3fly node
    ///
    /// # Arguments
    ///
    /// * `rho_code` - Rholang source code to deploy
    /// * `use_bigger_phlo_price` - Whether to use a larger phlo limit
    /// * `language` - Language of the deploy (typically "rholang")
    ///
    /// # Returns
    ///
    /// The deploy ID if successful, otherwise an error
    pub async fn deploy(
        &self,
        rho_code: &str,
        use_bigger_phlo_price: bool,
        language: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let phlo_limit: i64 = if use_bigger_phlo_price {
            5_000_000_000
        } else {
            100_000
        };

        // Get current block number for VABN (solves Block 50 issue)
        let current_block = match self.get_current_block_number().await {
            Ok(block_num) => {
                println!("🔢 Current block: {}", block_num);
                println!(
                    "✅ Setting validity window: blocks {} to {} (50-block window)",
                    block_num,
                    block_num + 50
                );
                block_num
            }
            Err(e) => {
                println!(
                    "⚠️  Warning: Could not get current block number ({}), using VABN=0",
                    e
                );
                println!("⚠️  This may cause Block 50 issues if blockchain has > 50 blocks");
                0
            }
        };

        // Build and sign the deployment
        let deployment = self.build_deploy_msg(
            rho_code.to_string(),
            phlo_limit,
            language.to_string(),
            current_block,
        );

        // Connect to the F1r3fly node
        let mut deploy_service_client =
            DeployServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        // Send the deploy
        let deploy_response = deploy_service_client.do_deploy(deployment).await?;

        // Process the response
        let deploy_message = deploy_response
            .get_ref()
            .message
            .as_ref()
            .ok_or("Deploy result not found")?;

        match deploy_message {
            DeployResponseMessage::Error(service_error) => Err(service_error.clone().into()),
            DeployResponseMessage::Result(result) => {
                // Extract the deploy ID from the response - handle various formats
                let cleaned_result = result.trim();

                // Try different possible prefixes and formats
                if let Some(deploy_id) = cleaned_result.strip_prefix("Success! DeployId is: ") {
                    Ok(deploy_id.trim().to_string())
                } else if let Some(deploy_id) =
                    cleaned_result.strip_prefix("Success!\nDeployId is: ")
                {
                    Ok(deploy_id.trim().to_string())
                } else if cleaned_result.starts_with("Success!") {
                    // Look for any long hex string in the response
                    let lines: Vec<&str> = cleaned_result.lines().collect();
                    for line in lines {
                        let trimmed = line.trim();
                        if trimmed.len() > 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Ok(trimmed.to_string());
                        }
                    }
                    Err(format!("Could not extract deploy ID from response: {}", result).into())
                } else {
                    // Assume it's already just the deploy ID
                    Ok(cleaned_result.to_string())
                }
            }
        }
    }

    /// Executes Rholang code without committing to the blockchain (exploratory deployment)
    ///
    /// # Arguments
    ///
    /// * `rho_code` - Rholang source code to execute
    /// * `block_hash` - Optional block hash to use as reference
    /// * `use_pre_state_hash` - Whether to use pre-state hash instead of post-state hash
    ///
    /// # Returns
    ///
    /// A tuple of (result data as JSON string, block info) if successful, otherwise an error
    pub async fn exploratory_deploy(
        &self,
        rho_code: &str,
        block_hash: Option<&str>,
        use_pre_state_hash: bool,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        // Connect to the F1r3fly node
        let mut deploy_service_client =
            DeployServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        // Build the exploratory deploy query
        let query = ExploratoryDeployQuery {
            term: rho_code.to_string(),
            block_hash: block_hash.unwrap_or("").to_string(),
            use_pre_state_hash,
        };

        // Send the exploratory deploy
        let response = deploy_service_client.exploratory_deploy(query).await?;

        // Process the response
        let message = response
            .get_ref()
            .message
            .as_ref()
            .ok_or("Exploratory deploy result not found")?;

        match message {
            ExploratoryDeployResponseMessage::Error(service_error) => {
                Err(service_error.clone().into())
            }
            ExploratoryDeployResponseMessage::Result(result) => {
                // Format the Par data structure to a readable string
                let data = {
                    let mut result_str = String::new();

                    // Process the data
                    if !result.post_block_data.is_empty() {
                        for (i, par) in result.post_block_data.iter().enumerate() {
                            if i > 0 {
                                result_str.push_str("\n");
                            }
                            // We're using a simplified representation of the Par data
                            // A more sophisticated approach would be to recursively traverse the structure
                            match extract_par_data(par) {
                                Some(data) => result_str.push_str(&data),
                                None => result_str
                                    .push_str(&format!("Result {}: Complex data structure", i + 1)),
                            }
                        }
                    } else {
                        result_str = "No data returned".to_string();
                    }

                    result_str
                };

                // Format the block info to a readable string
                let block_info = {
                    if let Some(block) = &result.block {
                        format!(
                            "Block hash: {}, Block number: {}",
                            block.block_hash, block.block_number
                        )
                    } else {
                        "No block info".to_string()
                    }
                };

                Ok((data, block_info))
            }
        }
    }

    /// Sends a proposal to the network to create a new block
    ///
    /// # Returns
    ///
    /// The block hash of the proposed block if successful, otherwise an error
    pub async fn propose(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Connect to the F1r3fly node's propose service
        let mut propose_client =
            ProposeServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        // Send the propose request
        let propose_response = propose_client
            .propose(ProposeQuery { is_async: false })
            .await?
            .into_inner();

        // Process the response
        let message = propose_response.message.ok_or("Missing propose response")?;

        match message {
            ProposeResponseMessage::Result(block_hash) => {
                // Extract the block hash from the response
                if let Some(hash) = block_hash
                    .strip_prefix("Success! Block ")
                    .and_then(|s| s.strip_suffix(" created and added."))
                {
                    Ok(hash.to_string())
                } else {
                    Ok(block_hash) // Return the full message if we can't extract the hash
                }
            }
            ProposeResponseMessage::Error(error) => {
                Err(format!("Propose error: {:?}", error).into())
            }
        }
    }

    /// Gets data sent to a deploy's `deployId` channel in a specific block.
    ///
    /// # Arguments
    ///
    /// * `deploy_id_hex` - The deploy ID (hex-encoded DER signature)
    /// * `block_hash` - The block hash to query
    ///
    /// # Returns
    ///
    /// A vector of string representations of the data sent to the deployId channel
    pub async fn get_data_at_deploy_id(
        &self,
        deploy_id_hex: &str,
        block_hash: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let deploy_id_bytes = hex::decode(deploy_id_hex)
            .map_err(|e| format!("Invalid deploy ID hex: {}", e))?;

        // Build a Par containing the unforgeable GDeployId name
        let par = Par {
            unforgeables: vec![GUnforgeable {
                unf_instance: Some(UnfInstance::GDeployIdBody(GDeployId {
                    sig: deploy_id_bytes.into(),
                })),
            }],
            ..Default::default()
        };

        let query = DataAtNameByBlockQuery {
            par: Some(par),
            block_hash: block_hash.to_string(),
            use_pre_state_hash: false,
        };

        let mut client =
            DeployServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        let response = client.get_data_at_name(query).await?;

        let message = response
            .get_ref()
            .message
            .as_ref()
            .ok_or("No response from getDataAtName")?;

        match message {
            RhoDataResponseMessage::Error(err) => {
                Err(format!("getDataAtName error: {}", err.messages.join("; ")).into())
            }
            RhoDataResponseMessage::Payload(payload) => {
                let mut results = Vec::new();
                for par in &payload.par {
                    match extract_par_data(par) {
                        Some(data) => results.push(data),
                        None => results.push(format!("{:?}", par)),
                    }
                }
                Ok(results)
            }
        }
    }

    /// Performs a full deployment cycle: deploy, propose, and listen for deployId data
    ///
    /// # Arguments
    ///
    /// * `rho_code` - Rholang source code to deploy
    /// * `use_bigger_phlo_price` - Whether to use a larger phlo limit
    /// * `language` - Language of the deploy (typically "rholang")
    ///
    /// # Returns
    ///
    /// A tuple of (block_hash, deploy_id, deployId_channel_data)
    pub async fn full_deploy(
        &self,
        rho_code: &str,
        use_bigger_phlo_price: bool,
        language: &str,
    ) -> Result<(String, String, Vec<String>), Box<dyn std::error::Error>> {
        // Deploy the code and get the deploy ID
        let deploy_id = self.deploy(rho_code, use_bigger_phlo_price, language).await?;

        // Try to propose, but if the node has auto-propose enabled the deploy will
        // be picked up automatically. In that case, skip propose and poll the HTTP
        // API to find which block contains our deploy.
        let http_port = self.grpc_port + 1;
        let mut block_hash = String::new();
        let mut auto_propose_mode = false;

        // First try a single propose
        match self.propose().await {
            Ok(hash) => {
                block_hash = hash;
            }
            Err(e) => {
                let msg = e.to_string();
                let is_auto_propose = msg.contains("NoNewDeploys")
                    || msg.contains("NotEnoughNewBlocks")
                    || msg.contains("another propose");

                if is_auto_propose {
                    println!("ℹ️  Propose not needed (node has auto-propose), waiting for deploy to land in a block...");
                    auto_propose_mode = true;
                } else {
                    return Err(e);
                }
            }
        }

        // If propose didn't give us a block hash, poll the HTTP API for it
        if block_hash.is_empty() {
            for poll in 1..=20 {
                match self.get_deploy_block_hash(&deploy_id, http_port).await {
                    Ok(Some(hash)) => {
                        println!("✅ Deploy included in block {}", &hash[..16.min(hash.len())]);
                        block_hash = hash;
                        break;
                    }
                    Ok(None) if poll < 20 => {
                        println!("⏳ Waiting for deploy to be included in a block... ({}/20)", poll);
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    }
                    Ok(None) => {
                        return Err("Deploy not included in any block after 60s of polling".into());
                    }
                    Err(poll_err) => {
                        if poll < 20 {
                            // HTTP API might not be ready yet, retry
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        } else {
                            return Err(format!(
                                "Failed to look up deploy block: {}", poll_err
                            ).into());
                        }
                    }
                }
            }
        }

        // On auto-propose shards, reductions can span multiple blocks (the bridge
        // contract's response may land in a block after the one that included the deploy).
        // Use the HTTP /api/data-at-name endpoint which searches across recent blocks.
        let data = if auto_propose_mode {
            self.poll_data_at_deploy_id_http(&deploy_id, http_port, 60, 2).await?
        } else {
            self.get_data_at_deploy_id(&deploy_id, &block_hash).await?
        };

        Ok((block_hash, deploy_id, data))
    }

    /// Poll the HTTP `/api/data-at-name` endpoint for data on a deploy's `deployId` channel.
    /// On auto-propose shards, reductions can span multiple blocks, so this polls until the
    /// data appears rather than querying a single specific block.
    pub async fn poll_data_at_deploy_id_http(
        &self,
        deploy_id_hex: &str,
        http_port: u16,
        max_attempts: u32,
        poll_interval_secs: u64,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = format!("http://{}:{}/api/data-at-name", self.node_host, http_port);

        let body = serde_json::json!({
            "depth": 50,
            "name": {
                "UnforgDeploy": {
                    "data": deploy_id_hex
                }
            }
        });

        for attempt in 1..=max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval_secs)).await;

            let resp = match client.post(&url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  HTTP poll attempt {}/{}: {}", attempt, max_attempts, e);
                    continue;
                }
            };

            let data: serde_json::Value = match resp.json().await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  HTTP poll attempt {}/{}: parse error: {}", attempt, max_attempts, e);
                    continue;
                }
            };

            let length = data.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
            if length == 0 {
                println!("⏳ Waiting for deployId data... ({}/{})", attempt, max_attempts);
                continue;
            }

            let mut results = Vec::new();
            if let Some(exprs) = data.get("exprs").and_then(|v| v.as_array()) {
                for expr in exprs {
                    if let Some(expr_obj) = expr.get("expr") {
                        for (_key, val) in expr_obj.as_object().into_iter().flat_map(|m| m.iter()) {
                            if let Some(d) = val.get("data") {
                                match d {
                                    serde_json::Value::Number(n) => results.push(n.to_string()),
                                    serde_json::Value::String(s) => results.push(s.clone()),
                                    serde_json::Value::Bool(b) => results.push(b.to_string()),
                                    other => results.push(other.to_string()),
                                }
                            }
                        }
                    }
                }
            }

            if !results.is_empty() {
                return Ok(results);
            }
            return Ok(vec![data.to_string()]);
        }

        Err(format!(
            "Timed out after {} attempts waiting for data at deploy {}",
            max_attempts, deploy_id_hex
        ).into())
    }

    /// Checks if a block is finalized, with retry logic
    ///
    /// # Arguments
    ///
    /// * `block_hash` - The hash of the block to check
    /// * `max_attempts` - Maximum number of retry attempts (default: 12)
    /// * `retry_delay_sec` - Delay between retries in seconds (default: 5)
    ///
    /// # Returns
    ///
    /// true if the block is finalized, false if the block is not finalized after all retry attempts
    pub async fn is_finalized(
        &self,
        block_hash: &str,
        max_attempts: u32,
        retry_delay_sec: u64,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut attempts = 0;

        loop {
            attempts += 1;

            // Connect to the F1r3fly node
            let mut deploy_service_client = DeployServiceClient::connect(format!(
                "http://{}:{}/",
                self.node_host, self.grpc_port
            ))
            .await?;

            // Query if the block is finalized
            let query = IsFinalizedQuery {
                hash: block_hash.to_string(),
            };

            match deploy_service_client.is_finalized(query).await {
                Ok(response) => {
                    let finalized_response = response.get_ref();
                    if let Some(message) = &finalized_response.message {
                        match message {
                            IsFinalizedResponseMessage::Error(_) => {
                                return Err("Error checking finalization status".into());
                            }
                            IsFinalizedResponseMessage::IsFinalized(is_finalized) => {
                                if *is_finalized {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if attempts >= max_attempts {
                        return Err("Failed to connect to node after maximum attempts".into());
                    }
                }
            }

            if attempts >= max_attempts {
                return Ok(false);
            }

            // Wait before retrying
            tokio::time::sleep(tokio::time::Duration::from_secs(retry_delay_sec)).await;
        }
    }

    /// Get the block hash for a given deploy ID by querying the HTTP API
    ///
    /// # Arguments
    ///
    /// * `deploy_id` - The deploy ID to look up
    /// * `http_port` - The HTTP port for the deploy API endpoint
    ///
    /// # Returns
    ///
    /// Some(block_hash) if the deploy is included in a block, None if not yet included, or an error
    pub async fn get_deploy_block_hash(
        &self,
        deploy_id: &str,
        http_port: u16,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let url = format!(
            "http://{}:{}/api/deploy/{}",
            self.node_host, http_port, deploy_id
        );
        let client = reqwest::Client::new();

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let deploy_info: serde_json::Value = response.json().await?;

                    // Extract blockHash from the response
                    if let Some(block_hash) = deploy_info.get("blockHash").and_then(|v| v.as_str())
                    {
                        Ok(Some(block_hash.to_string()))
                    } else {
                        Ok(None) // Deploy exists but no blockHash yet
                    }
                } else if response.status().as_u16() == 404 {
                    Ok(None) // Deploy not found yet
                } else {
                    let status = response.status();
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unable to read response body".to_string());

                    // Handle the case where the deploy exists but isn't in a block yet
                    if error_body.contains("Couldn't find block containing deploy with id:") {
                        Ok(None) // Deploy exists but not in a block yet
                    } else {
                        Err(format!(
                            "HTTP error {}: {} - Response: {}",
                            status,
                            status.canonical_reason().unwrap_or("Unknown"),
                            error_body
                        )
                        .into())
                    }
                }
            }
            Err(e) => Err(format!("Network error: {}", e).into()),
        }
    }

    /// Gets comprehensive information about a deploy by ID
    ///
    /// # Arguments
    ///
    /// * `deploy_id` - The deploy ID to look up
    /// * `http_port` - HTTP port for API queries
    ///
    /// # Returns
    ///
    /// DeployInfo struct with deploy details and status
    pub async fn get_deploy_info(
        &self,
        deploy_id: &str,
        http_port: u16,
    ) -> Result<DeployInfo, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();

        // Step 1: Get block hash from /api/deploy/{id}
        let deploy_url = format!(
            "http://{}:{}/api/deploy/{}",
            self.node_host, http_port, deploy_id
        );

        let deploy_response = match client.get(&deploy_url).send().await {
            Ok(response) => response,
            Err(e) => {
                return Ok(DeployInfo {
                    deploy_id: deploy_id.to_string(),
                    block_hash: None,
                    sender: None,
                    seq_num: None,
                    sig: None,
                    sig_algorithm: None,
                    shard_id: None,
                    version: None,
                    timestamp: None,
                    status: DeployStatus::Error(format!("Network error: {}", e)),
                    errored: false,
                    system_deploy_error: None,
                });
            }
        };

        if deploy_response.status().as_u16() == 404 {
            return Ok(DeployInfo {
                deploy_id: deploy_id.to_string(),
                block_hash: None,
                sender: None,
                seq_num: None,
                sig: None,
                sig_algorithm: None,
                shard_id: None,
                version: None,
                timestamp: None,
                status: DeployStatus::NotFound,
                errored: false,
                system_deploy_error: None,
            });
        }

        if !deploy_response.status().is_success() {
            let error_body = deploy_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());

            if error_body.contains("Couldn't find block containing deploy with id:") {
                return Ok(DeployInfo {
                    deploy_id: deploy_id.to_string(),
                    block_hash: None,
                    sender: None,
                    seq_num: None,
                    sig: None,
                    sig_algorithm: None,
                    shard_id: None,
                    version: None,
                    timestamp: None,
                    status: DeployStatus::Pending,
                    errored: false,
                    system_deploy_error: None,
                });
            }

            return Ok(DeployInfo {
                deploy_id: deploy_id.to_string(),
                block_hash: None,
                sender: None,
                seq_num: None,
                sig: None,
                sig_algorithm: None,
                shard_id: None,
                version: None,
                timestamp: None,
                status: DeployStatus::Error(format!("HTTP error: {}", error_body)),
                errored: false,
                system_deploy_error: None,
            });
        }

        let deploy_data: serde_json::Value = deploy_response.json().await?;
        let block_hash = deploy_data
            .get("blockHash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Step 2: Get full block info to find deploy details with systemDeployError
        let (errored, system_deploy_error) = if let Some(ref bh) = block_hash {
            let block_url = format!("http://{}:{}/api/block/{}", self.node_host, http_port, bh);

            match client.get(&block_url).send().await {
                Ok(block_response) if block_response.status().is_success() => {
                    let block_data: serde_json::Value = block_response.json().await?;

                    // Find our deploy in the block's deploys array by matching sig
                    let deploy_details = block_data
                        .get("deploys")
                        .and_then(|d| d.as_array())
                        .and_then(|deploys| {
                            deploys.iter().find(|d| {
                                d.get("sig")
                                    .and_then(|s| s.as_str())
                                    .map(|s| s == deploy_id)
                                    .unwrap_or(false)
                            })
                        });

                    if let Some(details) = deploy_details {
                        let errored = details
                            .get("errored")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let system_error = details
                            .get("systemDeployError")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string());
                        (errored, system_error)
                    } else {
                        (false, None)
                    }
                }
                _ => (false, None),
            }
        } else {
            (false, None)
        };

                    // Parse the response into DeployInfo
                    let deploy_info = DeployInfo {
                        deploy_id: deploy_id.to_string(),
            block_hash,
                        sender: deploy_data
                            .get("sender")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        seq_num: deploy_data.get("seqNum").and_then(|v| v.as_u64()),
                        sig: deploy_data
                            .get("sig")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        sig_algorithm: deploy_data
                            .get("sigAlgorithm")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        shard_id: deploy_data
                            .get("shardId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        version: deploy_data.get("version").and_then(|v| v.as_u64()),
                        timestamp: deploy_data.get("timestamp").and_then(|v| v.as_u64()),
                        status: DeployStatus::Included,
            errored,
            system_deploy_error,
                    };
                    Ok(deploy_info)
    }

    /// Gets blocks in the main chain
    ///
    /// # Arguments
    ///
    /// * `depth` - Number of blocks to retrieve from the main chain
    ///
    /// # Returns
    ///
    /// A vector of LightBlockInfo representing blocks in the main chain
    pub async fn show_main_chain(
        &self,
        depth: u32,
    ) -> Result<Vec<LightBlockInfo>, Box<dyn std::error::Error>> {
        use f1r3fly_models::casper::v1::block_info_response::Message;
        use f1r3fly_models::casper::v1::deploy_service_client::DeployServiceClient;

        // Connect to the F1r3fly node
        let mut deploy_service_client =
            DeployServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        // Create the query
        let query = BlocksQuery {
            depth: depth as i32,
        };

        // Send the query and collect streaming response
        let mut stream = deploy_service_client
            .show_main_chain(query)
            .await?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(response) = stream.message().await? {
            if let Some(message) = response.message {
                match message {
                    Message::Error(service_error) => {
                        return Err(
                            format!("gRPC Error: {}", service_error.messages.join("; ")).into()
                        );
                    }
                    Message::BlockInfo(block_info) => {
                        blocks.push(block_info);
                    }
                }
            }
        }

        Ok(blocks)
    }

    /// Gets blocks by height range from the blockchain
    ///
    /// # Arguments
    ///
    /// * `start_block_number` - Start block number (inclusive)
    /// * `end_block_number` - End block number (inclusive)
    ///
    /// # Returns
    ///
    /// A vector of LightBlockInfo representing blocks in the specified height range
    pub async fn get_blocks_by_height(
        &self,
        start_block_number: i64,
        end_block_number: i64,
    ) -> Result<Vec<LightBlockInfo>, Box<dyn std::error::Error>> {
        use f1r3fly_models::casper::v1::block_info_response::Message;
        use f1r3fly_models::casper::v1::deploy_service_client::DeployServiceClient;

        // Connect to the F1r3fly node
        let mut deploy_service_client =
            DeployServiceClient::connect(format!("http://{}:{}/", self.node_host, self.grpc_port))
                .await?;

        // Create the query
        let query = BlocksQueryByHeight {
            start_block_number,
            end_block_number,
        };

        // Send the query and collect streaming response
        let mut stream = deploy_service_client
            .get_blocks_by_heights(query)
            .await?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(response) = stream.message().await? {
            if let Some(message) = response.message {
                match message {
                    Message::Error(service_error) => {
                        return Err(
                            format!("gRPC Error: {}", service_error.messages.join("; ")).into()
                        );
                    }
                    Message::BlockInfo(block_info) => {
                        blocks.push(block_info);
                    }
                }
            }
        }

        Ok(blocks)
    }

    /// Gets the current block number from the blockchain
    ///
    /// # Returns
    ///
    /// The current block number if successful, otherwise an error
    pub async fn get_current_block_number(&self) -> Result<i64, Box<dyn std::error::Error>> {
        // Get the most recent block using show_main_chain with depth 1
        let blocks = self.show_main_chain(1).await?;

        if let Some(latest_block) = blocks.first() {
            Ok(latest_block.block_number)
        } else {
            // Fallback to 0 if no blocks found (genesis case)
            Ok(0)
        }
    }

    /// Builds and signs a deploy message
    ///
    /// # Arguments
    ///
    /// * `code` - Rholang source code to deploy
    /// * `phlo_limit` - Maximum amount of phlo to use for execution
    /// * `language` - Language of the deploy (typically "rholang")
    /// * `valid_after_block_number` - Block number after which the deploy is valid
    ///
    /// # Returns
    ///
    /// A signed `DeployDataProto` ready to be sent to the node
    fn build_deploy_msg(
        &self,
        code: String,
        phlo_limit: i64,
        language: String,
        valid_after_block_number: i64,
    ) -> DeployDataProto {
        // Get current timestamp in milliseconds
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get system time")
            .as_millis() as i64;

        // Create a projection with the fields used for signature calculation
        // NOTE: language IS included because the current Docker image (pre-80c9bc2a)
        // includes it in DeployData's ToMessage serialization
        let projection = DeployDataProto {
            term: code.clone(),
            timestamp,
            phlo_price: 1,
            phlo_limit,
            valid_after_block_number,
            shard_id: "root".into(),
            language:  String::new(), // language.clone(),
            sig: ByteString::new(),
            deployer: ByteString::new(),
            sig_algorithm: String::new(),
        };

        // Serialize the projection for hashing
        let serialized = projection.encode_to_vec();

        // Hash with Blake2b256
        let digest = blake2b_256_hash(&serialized);

        // Sign the digest with k256 (same library as the node uses for verification)
        let signature: K256Signature = self
            .signing_key
            .sign_prehash(&digest)
            .expect("Failed to sign deploy");

        // Get signature in DER format
        let sig_bytes = signature.to_der().as_bytes().to_vec();

        // Get the public key in uncompressed SEC1 format
        let public_key = self.signing_key.verifying_key().to_encoded_point(false);
        let pub_key_bytes = public_key.as_bytes().to_vec();

        // Return the complete deploy message
        DeployDataProto {
            term: code,
            timestamp,
            phlo_price: 1,
            phlo_limit,
            valid_after_block_number,
            shard_id: "root".into(),
            language,
            sig: ByteString::from(sig_bytes),
            sig_algorithm: "secp256k1".into(),
            deployer: ByteString::from(pub_key_bytes),
        }
    }
}

/// Extracts a simplified string representation from a Par object
fn extract_par_data(par: &Par) -> Option<String> {
    use f1r3fly_models::rhoapi::expr::ExprInstance;

    // Check for expressions
    if !par.exprs.is_empty() && par.exprs[0].expr_instance.is_some() {
        let expr = &par.exprs[0];
        if let Some(instance) = &expr.expr_instance {
            match instance {
                ExprInstance::GString(s) => Some(format!("\"{}\"", s)),
                ExprInstance::GUri(u) => Some(format!("`{}`", u)),
                ExprInstance::GInt(i) => Some(i.to_string()),
                ExprInstance::GBool(b) => Some(b.to_string()),
                ExprInstance::GByteArray(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                ExprInstance::EListBody(list) => {
                    let items: Vec<String> = list
                        .ps
                        .iter()
                        .map(|p| extract_par_data(p).unwrap_or_else(|| format!("{:?}", p)))
                        .collect();
                    Some(format!("[{}]", items.join(", ")))
                }
                ExprInstance::ETupleBody(tuple) => {
                    let items: Vec<String> = tuple
                        .ps
                        .iter()
                        .map(|p| extract_par_data(p).unwrap_or_else(|| format!("{:?}", p)))
                        .collect();
                    Some(format!("({})", items.join(", ")))
                }
                ExprInstance::EMapBody(map) => {
                    let items: Vec<String> = map
                        .kvs
                        .iter()
                        .map(|kv| {
                            let key = kv
                                .key
                                .as_ref()
                                .and_then(extract_par_data)
                                .unwrap_or_else(|| "?".to_string());
                            let val = kv
                                .value
                                .as_ref()
                                .and_then(extract_par_data)
                                .unwrap_or_else(|| "?".to_string());
                            format!("{}: {}", key, val)
                        })
                        .collect();
                    Some(format!("{{{}}}", items.join(", ")))
                }
                _ => Some(format!("{:?}", instance)),
            }
        } else {
            None
        }
    }
    // Check for unforgeable names
    else if !par.unforgeables.is_empty() {
        let unf = &par.unforgeables[0];
        match &unf.unf_instance {
            Some(UnfInstance::GDeployIdBody(id)) => {
                Some(format!("DeployId({})", hex::encode(&id.sig)))
            }
            Some(UnfInstance::GPrivateBody(p)) => {
                Some(format!("GPrivate({})", hex::encode(&p.id)))
            }
            _ => Some(format!("{:?}", unf)),
        }
    }
    // Check for sends
    else if !par.sends.is_empty() {
        Some("Send operation".to_string())
    }
    // Check for receives
    else if !par.receives.is_empty() {
        Some("Receive operation".to_string())
    }
    // Check for news
    else if !par.news.is_empty() {
        Some("New declaration".to_string())
    }
    // Empty or unsupported Par object
    else {
        None
    }
}

/// Computes a Blake2b 256-bit hash of the provided data
fn blake2b_256_hash(data: &[u8]) -> [u8; 32] {
    let mut blake = Blake2b::<U32>::new();
    blake.update(data);
    let hash = blake.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}
