use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyClass {
    Safe,
    Controlled,
    Disruptive,
    LabOnly,
}

impl SafetyClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Controlled => "controlled",
            Self::Disruptive => "disruptive",
            Self::LabOnly => "lab-only",
        }
    }
}

impl fmt::Display for SafetyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCategory {
    StaticAnalysis,
    SupplyChain,
    Cryptography,
    Parser,
    Fuzzing,
    LocalIpc,
    Filesystem,
    NetworkApi,
    SecretLeakage,
    MemoryLifecycle,
    FaultInjection,
    ResourceExhaustion,
    AccessControl,
    ReleaseIntegrity,
    LabOrchestration,
}

impl TestCategory {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StaticAnalysis => "STATIC",
            Self::SupplyChain => "SUPPLY",
            Self::Cryptography => "CRYPTO",
            Self::Parser => "PARSER",
            Self::Fuzzing => "FUZZ",
            Self::LocalIpc => "IPC",
            Self::Filesystem => "FS",
            Self::NetworkApi => "API",
            Self::SecretLeakage => "LEAK",
            Self::MemoryLifecycle => "MEMORY",
            Self::FaultInjection => "FAULT",
            Self::ResourceExhaustion => "RESOURCE",
            Self::AccessControl => "ACL",
            Self::ReleaseIntegrity => "RELEASE",
            Self::LabOrchestration => "LAB",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionModel {
    BlackBox,
    WhiteBox,
    Hybrid,
}

impl ExecutionModel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlackBox => "black-box",
            Self::WhiteBox => "white-box",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub category: TestCategory,
    pub safety: SafetyClass,
    pub model: ExecutionModel,
}

impl TestDescriptor {
    #[must_use]
    pub const fn new(
        id: &'static str,
        name: &'static str,
        category: TestCategory,
        safety: SafetyClass,
        model: ExecutionModel,
    ) -> Self {
        Self {
            id,
            name,
            category,
            safety,
            model,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPolicy {
    maximum_class: SafetyClass,
    lab_acknowledged: bool,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self::safe_only()
    }
}

impl ExecutionPolicy {
    #[must_use]
    pub const fn safe_only() -> Self {
        Self {
            maximum_class: SafetyClass::Safe,
            lab_acknowledged: false,
        }
    }

    #[must_use]
    pub const fn controlled() -> Self {
        Self {
            maximum_class: SafetyClass::Controlled,
            lab_acknowledged: false,
        }
    }

    #[must_use]
    pub const fn disruptive() -> Self {
        Self {
            maximum_class: SafetyClass::Disruptive,
            lab_acknowledged: false,
        }
    }

    #[must_use]
    pub const fn lab_only_acknowledged() -> Self {
        Self {
            maximum_class: SafetyClass::LabOnly,
            lab_acknowledged: true,
        }
    }

    #[must_use]
    pub const fn allows(self, class: SafetyClass) -> bool {
        if matches!(class, SafetyClass::LabOnly) && !self.lab_acknowledged {
            return false;
        }
        class as u8 <= self.maximum_class as u8
    }

    #[must_use]
    pub const fn maximum_class(self) -> SafetyClass {
        self.maximum_class
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    Pass,
    Fail,
    Warning,
    Skipped,
    InfrastructureError,
}

impl TestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Warning => "warning",
            Self::Skipped => "skipped",
            Self::InfrastructureError => "infrastructure-error",
        }
    }

    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail | Self::InfrastructureError)
    }
}
