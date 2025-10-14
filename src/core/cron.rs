//! Cron job orchestrator for HARDN
//!
//! Coordinates recurring maintenance jobs that keep Legion telemetry, HARDN service
//! state, and auxiliary security tooling fresh. Designed to run inside long-lived
//! processes (for example the Legion daemon) so scheduled tasks execute even when
//! traditional system cron is unavailable.

use chrono::{DateTime, Datelike, Duration as ChronoDuration, Local, TimeZone, Timelike, Weekday};
use log::{error, info};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Supported cron-like schedules. Additional variants can be added without
/// changing orchestrator logic.
#[derive(Clone, Copy, Debug)]
pub enum CronSchedule {
    /// Run once per day at the given time.
    Daily { hour: u32, minute: u32 },
    /// Run once per week on the provided weekday and time.
    Weekly {
        weekday: Weekday,
        hour: u32,
        minute: u32,
    },
}

impl CronSchedule {
    fn latest_occurrence(&self, now: DateTime<Local>) -> Option<DateTime<Local>> {
        match *self {
            CronSchedule::Daily { hour, minute } => {
                let candidate = now
                    .with_hour(hour)?
                    .with_minute(minute)?
                    .with_second(0)?
                    .with_nanosecond(0)?;
                if candidate <= now {
                    Some(candidate)
                } else {
                    Some(candidate - ChronoDuration::days(1))
                }
            }
            CronSchedule::Weekly {
                weekday,
                hour,
                minute,
            } => {
                let today = now.weekday();
                let mut days_back =
                    (7 + today.num_days_from_monday() - weekday.num_days_from_monday()) % 7;

                let mut candidate_date = now.date_naive() - ChronoDuration::days(days_back as i64);
                let mut candidate_time = candidate_date.and_hms_opt(hour, minute, 0)?;
                let mut candidate = Local.from_local_datetime(&candidate_time).single()?;

                if candidate > now {
                    days_back += 7;
                    candidate_date = now.date_naive() - ChronoDuration::days(days_back as i64);
                    candidate_time = candidate_date.and_hms_opt(hour, minute, 0)?;
                    candidate = Local.from_local_datetime(&candidate_time).single()?;
                }

                Some(candidate)
            }
        }
    }
}

impl fmt::Display for CronSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CronSchedule::Daily { hour, minute } => {
                write!(f, "daily at {:02}:{:02}", hour, minute)
            }
            CronSchedule::Weekly {
                weekday,
                hour,
                minute,
            } => write!(f, "weekly on {} at {:02}:{:02}", weekday, hour, minute),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CronJob {
    pub name: String,
    pub description: String,
    pub schedule: CronSchedule,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub environment: HashMap<String, String>,
    pub log_file: PathBuf,
}

impl CronJob {
    pub fn daily_job<S: Into<String>, D: Into<String>, P: AsRef<Path>>(
        name: S,
        description: D,
        log_root: P,
        log_file: &str,
        hour: u32,
        minute: u32,
        command: &str,
        args: &[&str],
    ) -> Self {
        Self::new(
            name,
            description,
            CronSchedule::Daily { hour, minute },
            log_root,
            log_file,
            command,
            args,
        )
    }

    pub fn weekly_job<S: Into<String>, D: Into<String>, P: AsRef<Path>>(
        name: S,
        description: D,
        log_root: P,
        log_file: &str,
        weekday: Weekday,
        hour: u32,
        minute: u32,
        command: &str,
        args: &[&str],
    ) -> Self {
        Self::new(
            name,
            description,
            CronSchedule::Weekly {
                weekday,
                hour,
                minute,
            },
            log_root,
            log_file,
            command,
            args,
        )
    }

    fn new<S: Into<String>, D: Into<String>, P: AsRef<Path>>(
        name: S,
        description: D,
        schedule: CronSchedule,
        log_root: P,
        log_file: &str,
        command: &str,
        args: &[&str],
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            schedule,
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            working_dir: None,
            environment: HashMap::new(),
            log_file: log_root.as_ref().join(log_file),
        }
    }

    fn ensure_log_directory(&self) {
        if let Some(parent) = self.log_file.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                error!(
                    "Unable to create cron log directory for {}: {}",
                    self.name, err
                );
            }
        }
    }

    fn execute(&self) -> CronRunOutcome {
        self.ensure_log_directory();
        let start = Instant::now();
        let started_ts = Local::now();

        let mut log_handle = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
        {
            Ok(file) => Some(file),
            Err(err) => {
                error!(
                    "Unable to open cron log file {}: {}",
                    self.log_file.display(),
                    err
                );
                None
            }
        };

        if let Some(log) = log_handle.as_mut() {
            let _ = writeln!(
                log,
                "[{}] === {} ({}) ===",
                started_ts.to_rfc3339(),
                self.name,
                self.description
            );
        }

        let mut command = Command::new(&self.command);
        command.args(&self.args);

        if let Some(dir) = &self.working_dir {
            command.current_dir(dir);
        }

        for (key, value) in &self.environment {
            command.env(key, value);
        }

        let outcome = match command.output() {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);

                if let Some(log) = log_handle.as_mut() {
                    if !stdout.trim().is_empty() {
                        let _ = writeln!(log, "--- STDOUT ---\n{}", stdout);
                    }
                    if !stderr.trim().is_empty() {
                        let _ = writeln!(log, "--- STDERR ---\n{}", stderr);
                    }
                }

                CronRunOutcome {
                    success: result.status.success(),
                    exit_code: result.status.code(),
                    duration: start.elapsed(),
                }
            }
            Err(err) => {
                if let Some(log) = log_handle.as_mut() {
                    let _ = writeln!(log, "Command failed to spawn: {}", err);
                } else {
                    error!("Cron job '{}' failed to spawn: {}", self.name, err);
                }

                CronRunOutcome {
                    success: false,
                    exit_code: None,
                    duration: start.elapsed(),
                }
            }
        };

        if let Some(log) = log_handle.as_mut() {
            let _ = writeln!(
                log,
                "[{}] === completed in {:.2?}, success={} ===\n",
                Local::now().to_rfc3339(),
                outcome.duration,
                outcome.success
            );
        }

        outcome
    }
}

#[derive(Debug, Default)]
struct JobState {
    last_run: Option<DateTime<Local>>,
    last_success: Option<bool>,
}

struct ScheduledJob {
    job: CronJob,
    state: Mutex<JobState>,
}

impl ScheduledJob {
    fn new(job: CronJob) -> Self {
        Self {
            job,
            state: Mutex::new(JobState::default()),
        }
    }

    fn maybe_run<F>(&self, now: DateTime<Local>, mut on_complete: F)
    where
        F: FnMut(&CronJob, DateTime<Local>, &CronRunOutcome),
    {
        let latest_slot = match self.job.schedule.latest_occurrence(now) {
            Some(slot) => slot,
            None => return,
        };

        {
            let state = self.state.lock().unwrap();
            if let Some(last_run) = state.last_run {
                if last_run >= latest_slot {
                    return;
                }
            }
        }

        info!("Cron job '{}' due (slot {:?})", self.job.name, latest_slot);
        let outcome = self.job.execute();
        let completed_at = Local::now();

        {
            let mut state = self.state.lock().unwrap();
            state.last_run = Some(completed_at);
            state.last_success = Some(outcome.success);
        }

        if outcome.success {
            info!(
                "Cron job '{}' completed successfully in {:.2?}",
                self.job.name, outcome.duration
            );
        } else {
            error!(
                "Cron job '{}' exited with failure (code: {:?})",
                self.job.name, outcome.exit_code
            );
        }

        on_complete(&self.job, completed_at, &outcome);
    }
}

/// Execution summary for a cron job invocation.
#[derive(Debug, Clone)]
pub struct CronRunOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize)]
struct CronSummaryEntry {
    name: String,
    description: String,
    schedule: String,
    command: String,
    args: Vec<String>,
    log_file: String,
    last_run: Option<String>,
    last_success: Option<bool>,
    last_exit_code: Option<i32>,
    last_duration_seconds: Option<f64>,
}

impl CronSummaryEntry {
    fn new(job: &CronJob) -> Self {
        Self {
            name: job.name.clone(),
            description: job.description.clone(),
            schedule: job.schedule.to_string(),
            command: job.command.clone(),
            args: job.args.clone(),
            log_file: job.log_file.display().to_string(),
            last_run: None,
            last_success: None,
            last_exit_code: None,
            last_duration_seconds: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct CronSummaryFile {
    generated_at: String,
    jobs: Vec<CronSummaryEntry>,
}

/// Orchestrates a collection of scheduled jobs.  Polls for due jobs on a fixed
/// interval and executes them sequentially.
pub struct CronOrchestrator {
    jobs: Vec<Arc<ScheduledJob>>,
    poll_interval: Duration,
    state_path: PathBuf,
    summary: Arc<Mutex<HashMap<String, CronSummaryEntry>>>,
}

impl CronOrchestrator {
    /// Creates an orchestrator populated with the standard HARDN schedule.
    pub fn standard_profile<P: AsRef<Path>, Q: AsRef<Path>>(log_root: P, state_path: Q) -> Self {
        let log_root = log_root.as_ref().to_path_buf();
        let state_path = state_path.as_ref().to_path_buf();
        let summary = Arc::new(Mutex::new(HashMap::new()));
        let mut jobs: Vec<Arc<ScheduledJob>> = Vec::new();

        // Weekly posture and tooling maintenance
        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "hardn-security-report",
            "Generate HARDN security snapshot",
            &log_root,
            "hardn-security-report.log",
            Weekday::Sun,
            2,
            0,
            "/usr/bin/hardn",
            &["--security-report", "--json"],
        ))));

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "hardn-run-modules",
            "Execute HARDN hardening modules",
            &log_root,
            "hardn-run-modules.log",
            Weekday::Sun,
            3,
            0,
            "/usr/bin/hardn",
            &["--run-all-modules", "--noninteractive"],
        ))));

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "aide-check",
            "Run AIDE integrity verification",
            &log_root,
            "aide-check.log",
            Weekday::Sun,
            4,
            0,
            "/usr/bin/aide",
            &["--check"],
        ))));

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "rkhunter",
            "Update and execute RKHunter",
            &log_root,
            "rkhunter.log",
            Weekday::Sun,
            5,
            0,
            "/bin/bash",
            &["-c", "rkhunter --update && rkhunter --check --sk --cronjob"],
        ))));

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "lynis-audit",
            "Run Lynis hardening audit",
            &log_root,
            "lynis-audit.log",
            Weekday::Sun,
            6,
            0,
            "/usr/local/bin/lynis-audit.sh",
            &[],
        ))));

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "fail2ban-health",
            "Capture Fail2Ban service status",
            &log_root,
            "fail2ban-status.log",
            Weekday::Sun,
            7,
            0,
            "/bin/bash",
            &[
                "-c",
                "systemctl status --no-pager fail2ban && fail2ban-client status || true",
            ],
        ))));

        let clamscan_log = log_root.join("clamav-weekly.log");
        let clamscan_arg = format!(
            "clamscan -ri / --log=\"{}\" --exclude-dir=\"^/sys\" --exclude-dir=\"^/proc\" --exclude-dir=\"^/run\"",
            clamscan_log.display()
        );

        jobs.push(Arc::new(ScheduledJob::new(CronJob::weekly_job(
            "clamav-scan",
            "Run full ClamAV malware scan",
            &log_root,
            "clamav-scan.log",
            Weekday::Sun,
            23,
            30,
            "/bin/bash",
            &["-c", &clamscan_arg],
        ))));

        // Daily Legion baseline snapshot (lightweight report)
        jobs.push(Arc::new(ScheduledJob::new(CronJob::daily_job(
            "legion-daily-baseline",
            "Create daily Legion baseline snapshot",
            &log_root,
            "legion-daily-baseline.log",
            1,
            30,
            "/usr/bin/hardn",
            &["legion", "--create-baseline", "--json"],
        ))));

        {
            let mut summary_guard = summary.lock().unwrap();
            for job in &jobs {
                summary_guard
                    .entry(job.job.name.clone())
                    .or_insert_with(|| CronSummaryEntry::new(&job.job));
            }
        }

        let orchestrator = Self {
            jobs,
            poll_interval: Duration::from_secs(60),
            state_path,
            summary,
        };

        let initial_snapshot = {
            let summary_guard = orchestrator.summary.lock().unwrap();
            summary_guard.values().cloned().collect::<Vec<_>>()
        };

        orchestrator.persist_summary(initial_snapshot);
        orchestrator
    }

    #[allow(dead_code)]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn start(self) -> JoinHandle<()> {
        thread::spawn(move || self.run_loop())
    }

    pub fn tick(&self, now: DateTime<Local>) {
        for job in &self.jobs {
            job.maybe_run(now, |descriptor, finished_at, outcome| {
                self.update_summary(descriptor, finished_at, outcome);
            });
        }
    }

    fn update_summary(&self, job: &CronJob, run_time: DateTime<Local>, outcome: &CronRunOutcome) {
        let mut summary = self.summary.lock().unwrap();
        let entry = summary
            .entry(job.name.clone())
            .or_insert_with(|| CronSummaryEntry::new(job));

        entry.last_run = Some(run_time.to_rfc3339());
        entry.last_success = Some(outcome.success);
        entry.last_exit_code = outcome.exit_code;
        entry.last_duration_seconds = Some(outcome.duration.as_secs_f64());

        let snapshot: Vec<CronSummaryEntry> = summary.values().cloned().collect();
        drop(summary);
        self.persist_summary(snapshot);
    }

    fn persist_summary(&self, snapshot: Vec<CronSummaryEntry>) {
        if let Some(parent) = self.state_path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                error!(
                    "Unable to create cron summary directory {}: {}",
                    parent.display(),
                    err
                );
                return;
            }
        }

        let doc = CronSummaryFile {
            generated_at: Local::now().to_rfc3339(),
            jobs: snapshot,
        };

        let tmp_path = self.state_path.with_extension("tmp");
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
        {
            Ok(mut file) => {
                if let Err(err) = serde_json::to_writer_pretty(&mut file, &doc) {
                    error!("Unable to write cron summary: {}", err);
                    let _ = fs::remove_file(&tmp_path);
                    return;
                }

                if let Err(err) = file.flush() {
                    error!("Unable to flush cron summary: {}", err);
                    let _ = fs::remove_file(&tmp_path);
                    return;
                }

                if let Err(err) = fs::rename(&tmp_path, &self.state_path) {
                    error!(
                        "Unable to finalize cron summary {}: {}",
                        self.state_path.display(),
                        err
                    );
                }
            }
            Err(err) => {
                error!(
                    "Unable to create cron summary {}: {}",
                    tmp_path.display(),
                    err
                );
            }
        }
    }

    fn run_loop(self) {
        loop {
            let now = Local::now();
            self.tick(now);
            thread::sleep(self.poll_interval);
        }
    }
}
