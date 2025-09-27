use std::process::Command;

/// Containers and build tooling monitoring
pub mod containers {
    use super::*;

    #[allow(dead_code)]
    pub fn check_docker_containers() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking Docker containers...");

        // Check if Docker is installed and running
        if Command::new("docker").arg("--version").output().is_err() {
            eprintln!("    Docker not installed");
            return Ok(());
        }

        // Check Docker daemon status
        if let Ok(output) = Command::new("systemctl").arg("is-active").arg("docker").output() {
            let status_output = String::from_utf8_lossy(&output.stdout);
            let status = status_output.trim();
            if status == "active" {
                eprintln!("    Docker daemon is running");
            } else {
                eprintln!("    Docker daemon is not running (status: {})", status);
            }
        }

        // Check running containers
        if let Ok(output) = Command::new("docker").arg("ps").arg("-a").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let container_count = output_str.lines().count().saturating_sub(1); // Subtract header

            eprintln!("    {} containers found", container_count);

            // Check for privileged containers
            if let Ok(output) = Command::new("docker").arg("ps").arg("--format").arg("table {{.Names}}\t{{.Status}}\t{{.Ports}}").output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines().skip(1) {
                    if line.contains("Up") {
                        eprintln!("    Running container: {}", line);
                    }
                }
            }

            // Check for privileged containers
            if let Ok(output) = Command::new("docker").arg("ps").arg("--quiet").arg("--filter").arg("privileged=true").output() {
                let privileged_count = String::from_utf8_lossy(&output.stdout).lines().count();
                if privileged_count > 0 {
                    eprintln!("    {} privileged containers running", privileged_count);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_podman_containers() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking Podman containers...");

        // Check if Podman is installed
        if Command::new("podman").arg("--version").output().is_err() {
            eprintln!("    Podman not installed");
            return Ok(());
        }

        // Check running containers
        if let Ok(output) = Command::new("podman").arg("ps").arg("-a").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let container_count = output_str.lines().count().saturating_sub(1);

            eprintln!("    {} containers found", container_count);

            // Check for privileged containers
            if let Ok(output) = Command::new("podman").arg("ps").arg("--quiet").arg("--filter").arg("privileged=true").output() {
                let privileged_count = String::from_utf8_lossy(&output.stdout).lines().count();
                if privileged_count > 0 {
                    eprintln!("    {} privileged containers running", privileged_count);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn check_build_tools() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("  Checking build tools...");

        let build_tools = vec!["make", "gcc", "g++", "clang", "rustc", "go", "python3", "node", "npm"];

        for tool in build_tools {
            if Command::new(tool).arg("--version").output().is_ok() {
                eprintln!("    {} is available", tool);
            } else {
                eprintln!("    {} not found", tool);
            }
        }

        Ok(())
    }
}