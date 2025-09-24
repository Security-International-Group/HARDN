use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use ndarray::Array2;
use linfa::prelude::*;
use linfa_clustering::KMeans;
use chrono::{DateTime, Utc};

/// Machine Learning enhanced baseline with anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLBaseline {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub normal_patterns: Vec<FeatureVector>,
    pub anomaly_threshold: f64,
    pub model_metadata: ModelMetadata,
    pub training_data_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub features: Vec<f64>,
    pub timestamp: DateTime<Utc>,
    pub system_state: SystemSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_connections: usize,
    pub running_processes: usize,
    pub open_files: usize,
    pub entropy: f64, // System randomness measure
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub algorithm: String,
    pub clusters: usize,
    pub features_count: usize,
    pub training_accuracy: f64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AnomalyScore {
    pub score: f64,
    pub confidence: f64,
    pub anomaly_type: AnomalyType,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum AnomalyType {
    Normal,
    Suspicious,
    Critical,
    Unknown,
}

impl MLBaseline {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            normal_patterns: Vec::new(),
            anomaly_threshold: 0.85,
            model_metadata: ModelMetadata {
                algorithm: "KMeans".to_string(),
                clusters: 5,
                features_count: 7,
                training_accuracy: 0.0,
            },
            training_data_size: 0,
        }
    }

    pub fn train(&mut self, historical_data: Vec<SystemSnapshot>) -> Result<(), Box<dyn std::error::Error>> {
        if historical_data.len() < 10 {
            return Err("Insufficient training data. Need at least 10 samples.".into());
        }

        // Convert system snapshots to feature vectors
        let mut feature_vectors = Vec::new();
        for snapshot in &historical_data {
            let features = vec![
                snapshot.cpu_usage,
                snapshot.memory_usage,
                snapshot.disk_usage,
                snapshot.network_connections as f64,
                snapshot.running_processes as f64,
                snapshot.open_files as f64,
                snapshot.entropy,
            ];
            // Skip invalid snapshots
            if features.iter().all(|&f| f.is_finite()) {
                feature_vectors.push(features);
            }
        }

        if feature_vectors.is_empty() {
            return Err("No valid training data available".into());
        }

        // Create dataset for ML training
        let dataset_size = feature_vectors.len();
        let feature_dim = feature_vectors[0].len();

        let mut dataset = Array2::<f64>::zeros((dataset_size, feature_dim));
        for (i, features) in feature_vectors.iter().enumerate() {
            for (j, &feature) in features.iter().enumerate() {
                dataset[[i, j]] = feature;
            }
        }

        // Train K-means clustering model
        let dataset = Dataset::from(dataset);
        let model = KMeans::params(self.model_metadata.clusters)
            .tolerance(1e-4)
            .max_n_iterations(100)
            .fit(&dataset)?;

        // Calculate training accuracy (inertia as proxy)
        let inertia = model.inertia();
        self.model_metadata.training_accuracy = 1.0 / (1.0 + inertia);

        // Store normal patterns
        self.normal_patterns = historical_data.into_iter()
            .enumerate()
            .map(|(_i, snapshot)| {
                let features = vec![
                    snapshot.cpu_usage,
                    snapshot.memory_usage,
                    snapshot.disk_usage,
                    snapshot.network_connections as f64,
                    snapshot.running_processes as f64,
                    snapshot.open_files as f64,
                    snapshot.entropy,
                ];
                FeatureVector {
                    features,
                    timestamp: Utc::now(),
                    system_state: snapshot,
                }
            })
            .collect();

        self.training_data_size = dataset_size;
        self.timestamp = Utc::now();

        Ok(())
    }

    pub fn detect_anomaly(&self, current_state: &SystemSnapshot) -> Result<AnomalyScore, Box<dyn std::error::Error>> {
        let features = vec![
            current_state.cpu_usage,
            current_state.memory_usage,
            current_state.disk_usage,
            current_state.network_connections as f64,
            current_state.running_processes as f64,
            current_state.open_files as f64,
            current_state.entropy,
        ];

        // Check for invalid values
        if features.iter().any(|&f| !f.is_finite()) {
            return Ok(AnomalyScore {
                score: 0.5,
                confidence: 0.5,
                anomaly_type: AnomalyType::Unknown,
                details: "Invalid system metrics detected".to_string(),
            });
        }

        // Calculate distance to nearest cluster centroid
        let mut min_distance = f64::INFINITY;
        for pattern in &self.normal_patterns {
            let distance = self.euclidean_distance(&features, &pattern.features);
            if distance < min_distance {
                min_distance = distance;
            }
        }

        // Check if min_distance is valid
        if !min_distance.is_finite() {
            return Ok(AnomalyScore {
                score: 0.5,
                confidence: 0.5,
                anomaly_type: AnomalyType::Unknown,
                details: "Unable to calculate anomaly distance".to_string(),
            });
        }

        // Normalize distance to anomaly score (0-1 scale)
        let max_expected_distance = 10.0; // Tunable parameter
        let anomaly_score = (min_distance / max_expected_distance).min(1.0);

        // Determine anomaly type and confidence
        let (anomaly_type, confidence, details) = if anomaly_score < 0.3 {
            (AnomalyType::Normal, 0.9, "System state within normal parameters".to_string())
        } else if anomaly_score < 0.7 {
            (AnomalyType::Suspicious, 0.7, format!("Potential anomaly detected (distance: {:.2})", min_distance))
        } else {
            (AnomalyType::Critical, 0.95, format!("Critical anomaly detected (distance: {:.2})", min_distance))
        };

        Ok(AnomalyScore {
            score: anomaly_score,
            confidence,
            anomaly_type,
            details,
        })
    }

    fn euclidean_distance(&self, a: &[f64], b: &[f64]) -> f64 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let baseline: MLBaseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }
}

/// ML Baseline Manager with training and prediction capabilities
#[derive(Debug)]
pub struct MLBaselineManager {
    baseline: Option<MLBaseline>,
    model_path: PathBuf,
    training_data: Vec<SystemSnapshot>,
}

#[allow(dead_code)]
impl MLBaselineManager {
    pub fn new(model_path: PathBuf) -> Self {
        Self {
            baseline: None,
            model_path,
            training_data: Vec::new(),
        }
    }

    pub fn add_training_sample(&mut self, snapshot: SystemSnapshot) {
        self.training_data.push(snapshot);
    }

    pub fn train_model(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut baseline = MLBaseline::new();
        baseline.train(self.training_data.clone())?;
        baseline.save(&self.model_path)?;
        self.baseline = Some(baseline);
        Ok(())
    }

    pub fn load_model(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.model_path.exists() {
            let baseline = MLBaseline::load(&self.model_path)?;
            self.baseline = Some(baseline);
        }
        Ok(())
    }

    pub fn predict_anomaly(&self, current_state: &SystemSnapshot) -> Result<AnomalyScore, Box<dyn std::error::Error>> {
        match &self.baseline {
            Some(baseline) => baseline.detect_anomaly(current_state),
            None => Err("No trained model available. Please train the model first.".into()),
        }
    }

    pub fn is_model_trained(&self) -> bool {
        self.baseline.is_some()
    }

    pub fn get_training_data_size(&self) -> usize {
        self.training_data.len()
    }
}