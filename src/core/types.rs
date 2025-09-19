/// Service status information
#[derive(Debug)]
pub struct ServiceStatus {
    #[allow(dead_code)]
    pub name: String,
    pub active: bool,
    pub enabled: bool,
    #[allow(dead_code)]
    pub description: String,
    pub pid: Option<u32>,
}

/// Security tool information
pub struct SecurityToolInfo {
    pub name: &'static str,
    pub service_name: &'static str,
    #[allow(dead_code)]
    pub process_name: &'static str,
    pub description: &'static str,
}

/// Tool category definition for scalable categorization
pub struct ToolCategory {
    pub name: &'static str,
    pub tools: Vec<&'static str>,
}

impl ToolCategory {
    pub fn new(name: &'static str, tools: Vec<&'static str>) -> Self {
        Self { name, tools }
    }
    
    pub fn contains(&self, tool: &str) -> bool {
        self.tools.iter().any(|&t| t == tool)
    }
}
