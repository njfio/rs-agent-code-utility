//! Semantic Embeddings Module
//!
//! This module provides semantic embedding generation using Candle-transformers
//! for advanced intent-to-implementation mapping. It replaces simple keyword
//! matching with sophisticated semantic similarity analysis.
//!
//! Features:
//! - Sentence embedding generation using BERT-based models
//! - Cosine similarity calculation for semantic matching
//! - Batch processing for efficient embedding generation
//! - Model caching and optimization
//! - Multi-language support for code and natural language text

use anyhow::{anyhow, Result};
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use hf_hub::api::tokio::Api;
use std::collections::HashMap;
use std::path::PathBuf;
use tokenizers::Tokenizer;

/// Configuration for semantic embeddings
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// Model name/path for embeddings
    pub model_name: String,
    /// Maximum sequence length
    pub max_length: usize,
    /// Batch size for processing
    pub batch_size: usize,
    /// Device to use (CPU/GPU)
    pub device: Device,
    /// Cache directory for models
    pub cache_dir: Option<PathBuf>,
    /// Similarity threshold for matching
    pub similarity_threshold: f64,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            model_name: "sentence-transformers/all-MiniLM-L6-v2".to_string(),
            max_length: 512,
            batch_size: 32,
            device: Device::Cpu,
            cache_dir: None,
            similarity_threshold: 0.7,
        }
    }
}

/// Semantic embedding vector
#[derive(Debug, Clone)]
pub struct Embedding {
    /// The embedding vector
    pub vector: Vec<f32>,
    /// Original text that was embedded
    pub text: String,
    /// Metadata about the embedding
    pub metadata: HashMap<String, String>,
}

impl Embedding {
    /// Create a new embedding
    pub fn new(vector: Vec<f32>, text: String) -> Self {
        Self {
            vector,
            text,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the embedding
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get the dimensionality of the embedding
    pub fn dimension(&self) -> usize {
        self.vector.len()
    }

    /// Calculate cosine similarity with another embedding
    pub fn cosine_similarity(&self, other: &Embedding) -> Result<f64> {
        if self.vector.len() != other.vector.len() {
            return Err(anyhow!("Embedding dimensions don't match: {} vs {}", 
                self.vector.len(), other.vector.len()));
        }

        let dot_product: f32 = self.vector.iter()
            .zip(other.vector.iter())
            .map(|(a, b)| a * b)
            .sum();

        let norm_a: f32 = self.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = other.vector.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return Ok(0.0);
        }

        Ok((dot_product / (norm_a * norm_b)) as f64)
    }
}

/// Semantic embedding engine using Candle-transformers
pub struct EmbeddingEngine {
    /// Configuration
    config: EmbeddingConfig,
    /// BERT model
    model: Option<BertModel>,
    /// Tokenizer
    tokenizer: Option<Tokenizer>,
    /// Device for computation
    device: Device,
    /// Model configuration
    bert_config: Option<Config>,
}

impl std::fmt::Debug for EmbeddingEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingEngine")
            .field("config", &self.config)
            .field("model_loaded", &self.model.is_some())
            .field("tokenizer_loaded", &self.tokenizer.is_some())
            .field("device", &format!("{:?}", self.device))
            .field("bert_config_loaded", &self.bert_config.is_some())
            .finish()
    }
}

impl EmbeddingEngine {
    /// Create a new embedding engine
    pub fn new(config: EmbeddingConfig) -> Self {
        let device = config.device.clone();
        Self {
            config,
            model: None,
            tokenizer: None,
            device,
            bert_config: None,
        }
    }

    /// Initialize the embedding engine (load model and tokenizer)
    pub async fn initialize(&mut self) -> Result<()> {
        // Download model files from Hugging Face Hub
        let api = Api::new()?;
        let repo = api.model(self.config.model_name.clone());

        // Download tokenizer
        let tokenizer_filename = repo.get("tokenizer.json").await?;
        self.tokenizer = Some(Tokenizer::from_file(tokenizer_filename)
            .map_err(|e| anyhow!("Failed to load tokenizer: {}", e))?);

        // Download model config
        let config_filename = repo.get("config.json").await?;
        let config_content = std::fs::read_to_string(config_filename)?;
        self.bert_config = Some(serde_json::from_str(&config_content)?);

        // Download model weights
        let weights_filename = match repo.get("pytorch_model.bin").await {
            Ok(path) => path,
            Err(_) => repo.get("model.safetensors").await?,
        };

        // Load model
        let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_filename], DTYPE, &self.device)? };
        self.model = Some(BertModel::load(vb, self.bert_config.as_ref().unwrap())?);

        Ok(())
    }

    /// Generate embeddings for a batch of texts
    pub fn embed_batch(&self, texts: &[String]) -> Result<Vec<Embedding>> {
        let model = self.model.as_ref()
            .ok_or_else(|| anyhow!("Model not initialized. Call initialize() first."))?;
        let tokenizer = self.tokenizer.as_ref()
            .ok_or_else(|| anyhow!("Tokenizer not initialized. Call initialize() first."))?;

        let mut embeddings = Vec::new();

        // Process texts in batches
        for chunk in texts.chunks(self.config.batch_size) {
            let batch_embeddings = self.process_batch(model, tokenizer, chunk)?;
            embeddings.extend(batch_embeddings);
        }

        Ok(embeddings)
    }

    /// Generate embedding for a single text
    pub fn embed(&self, text: &str) -> Result<Embedding> {
        let embeddings = self.embed_batch(&[text.to_string()])?;
        embeddings.into_iter().next()
            .ok_or_else(|| anyhow!("Failed to generate embedding"))
    }

    /// Process a batch of texts
    fn process_batch(
        &self,
        model: &BertModel,
        tokenizer: &Tokenizer,
        texts: &[String],
    ) -> Result<Vec<Embedding>> {
        // Tokenize texts
        let encodings = tokenizer.encode_batch(texts.to_vec(), true)
            .map_err(|e| anyhow!("Tokenization failed: {}", e))?;

        let mut input_ids = Vec::new();
        let mut attention_masks = Vec::new();

        for encoding in &encodings {
            let ids = encoding.get_ids();
            let attention_mask = encoding.get_attention_mask();

            // Pad or truncate to max_length
            let mut padded_ids = vec![0u32; self.config.max_length];
            let mut padded_mask = vec![0u32; self.config.max_length];

            let copy_len = ids.len().min(self.config.max_length);
            padded_ids[..copy_len].copy_from_slice(&ids[..copy_len]);
            padded_mask[..copy_len].copy_from_slice(&attention_mask[..copy_len]);

            input_ids.push(padded_ids);
            attention_masks.push(padded_mask);
        }

        // Convert to tensors
        let input_ids_tensor = Tensor::new(input_ids, &self.device)?;
        let attention_mask_tensor = Tensor::new(attention_masks, &self.device)?;

        // Run model
        let outputs = model.forward(&input_ids_tensor, &attention_mask_tensor, None)?;
        
        // Extract embeddings (use [CLS] token or mean pooling)
        let embeddings_tensor = self.mean_pooling(&outputs, &attention_mask_tensor)?;
        
        // Convert to Vec<f32>
        let embeddings_data = embeddings_tensor.to_vec2::<f32>()?;

        // Create Embedding objects
        let mut result = Vec::new();
        for (i, text) in texts.iter().enumerate() {
            let embedding = Embedding::new(embeddings_data[i].clone(), text.clone());
            result.push(embedding);
        }

        Ok(result)
    }

    /// Mean pooling of token embeddings
    fn mean_pooling(&self, token_embeddings: &Tensor, attention_mask: &Tensor) -> Result<Tensor> {
        // Expand attention mask to match token embeddings dimensions
        let expanded_mask = attention_mask.unsqueeze(2)?
            .expand(token_embeddings.shape())?;

        // Apply mask to embeddings
        let masked_embeddings = token_embeddings.mul(&expanded_mask)?;

        // Sum along sequence dimension
        let sum_embeddings = masked_embeddings.sum(1)?;

        // Sum attention mask to get actual lengths
        let sum_mask = attention_mask.sum(1)?;

        // Divide by actual lengths to get mean
        let mean_embeddings = sum_embeddings.div(&sum_mask.unsqueeze(1)?)?;

        Ok(mean_embeddings)
    }

    /// Calculate similarity between two texts
    pub fn calculate_similarity(&self, text1: &str, text2: &str) -> Result<f64> {
        let embedding1 = self.embed(text1)?;
        let embedding2 = self.embed(text2)?;
        embedding1.cosine_similarity(&embedding2)
    }

    /// Find most similar text from a collection
    pub fn find_most_similar(
        &self,
        query: &str,
        candidates: &[String],
    ) -> Result<Option<(String, f64)>> {
        let query_embedding = self.embed(query)?;
        let candidate_embeddings = self.embed_batch(candidates)?;

        let mut best_match = None;
        let mut best_score = 0.0;

        for (candidate, embedding) in candidates.iter().zip(candidate_embeddings.iter()) {
            let similarity = query_embedding.cosine_similarity(embedding)?;
            if similarity > best_score && similarity >= self.config.similarity_threshold {
                best_score = similarity;
                best_match = Some((candidate.clone(), similarity));
            }
        }

        Ok(best_match)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedding_creation() {
        let vector = vec![0.1, 0.2, 0.3, 0.4];
        let text = "test text".to_string();
        let embedding = Embedding::new(vector.clone(), text.clone());

        assert_eq!(embedding.vector, vector);
        assert_eq!(embedding.text, text);
        assert_eq!(embedding.dimension(), 4);
    }

    #[test]
    fn test_cosine_similarity() {
        let embedding1 = Embedding::new(vec![1.0, 0.0, 0.0], "text1".to_string());
        let embedding2 = Embedding::new(vec![0.0, 1.0, 0.0], "text2".to_string());
        let embedding3 = Embedding::new(vec![1.0, 0.0, 0.0], "text3".to_string());

        // Orthogonal vectors should have similarity 0
        let similarity1 = embedding1.cosine_similarity(&embedding2).unwrap();
        assert!((similarity1 - 0.0).abs() < 1e-6);

        // Identical vectors should have similarity 1
        let similarity2 = embedding1.cosine_similarity(&embedding3).unwrap();
        assert!((similarity2 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_embedding_config_default() {
        let config = EmbeddingConfig::default();
        assert_eq!(config.model_name, "sentence-transformers/all-MiniLM-L6-v2");
        assert_eq!(config.max_length, 512);
        assert_eq!(config.batch_size, 32);
        assert_eq!(config.similarity_threshold, 0.7);
    }

    #[test]
    fn test_embedding_with_metadata() {
        let vector = vec![0.1, 0.2, 0.3];
        let text = "test text".to_string();
        let embedding = Embedding::new(vector, text)
            .with_metadata("type".to_string(), "requirement".to_string())
            .with_metadata("id".to_string(), "REQ-001".to_string());

        assert_eq!(embedding.metadata.get("type"), Some(&"requirement".to_string()));
        assert_eq!(embedding.metadata.get("id"), Some(&"REQ-001".to_string()));
    }

    #[test]
    fn test_cosine_similarity_edge_cases() {
        // Test zero vectors
        let zero1 = Embedding::new(vec![0.0, 0.0, 0.0], "zero1".to_string());
        let zero2 = Embedding::new(vec![0.0, 0.0, 0.0], "zero2".to_string());
        let normal = Embedding::new(vec![1.0, 1.0, 1.0], "normal".to_string());

        // Zero vectors should return 0 similarity
        assert_eq!(zero1.cosine_similarity(&zero2).unwrap(), 0.0);
        assert_eq!(zero1.cosine_similarity(&normal).unwrap(), 0.0);

        // Test dimension mismatch
        let dim3 = Embedding::new(vec![1.0, 0.0, 0.0], "dim3".to_string());
        let dim4 = Embedding::new(vec![1.0, 0.0, 0.0, 0.0], "dim4".to_string());
        assert!(dim3.cosine_similarity(&dim4).is_err());
    }

    #[test]
    fn test_embedding_engine_creation() {
        let config = EmbeddingConfig::default();
        let engine = EmbeddingEngine::new(config.clone());

        assert_eq!(engine.config.model_name, config.model_name);
        assert!(engine.model.is_none());
        assert!(engine.tokenizer.is_none());
    }

    #[test]
    fn test_semantic_similarity_examples() {
        // Test semantic similarity with example texts
        let similar_texts = vec![
            ("user authentication", "login system"),
            ("database connection", "database connectivity"),
            ("error handling", "exception management"),
        ];

        for (text1, text2) in similar_texts {
            let embedding1 = Embedding::new(
                vec![0.8, 0.6, 0.2, 0.1], // Mock similar embeddings
                text1.to_string()
            );
            let embedding2 = Embedding::new(
                vec![0.7, 0.7, 0.3, 0.1], // Mock similar embeddings
                text2.to_string()
            );

            let similarity = embedding1.cosine_similarity(&embedding2).unwrap();
            // These should be reasonably similar (mock test)
            assert!(similarity > 0.5, "Expected similarity > 0.5 for '{}' and '{}', got {}", text1, text2, similarity);
        }
    }

    #[test]
    fn test_dissimilar_texts() {
        // Test dissimilar texts should have low similarity
        let embedding1 = Embedding::new(
            vec![1.0, 0.0, 0.0, 0.0], // Mock dissimilar embeddings
            "user authentication".to_string()
        );
        let embedding2 = Embedding::new(
            vec![0.0, 1.0, 0.0, 0.0], // Mock dissimilar embeddings
            "graphics rendering".to_string()
        );

        let similarity = embedding1.cosine_similarity(&embedding2).unwrap();
        assert_eq!(similarity, 0.0, "Expected 0 similarity for dissimilar texts");
    }
}
