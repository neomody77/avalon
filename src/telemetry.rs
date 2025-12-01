//! OpenTelemetry tracing integration
//!
//! Provides distributed tracing support via OpenTelemetry protocol (OTLP).
//! When enabled, traces are exported to an OTLP collector (e.g., Jaeger, Tempo).

use config::TracingConfig;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{Sampler, TracerProvider as SdkTracerProvider},
    Resource,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Initialize OpenTelemetry tracing
///
/// Returns a guard that should be kept alive for the duration of the program.
/// When dropped, it will flush any pending traces.
pub fn init_telemetry(config: &TracingConfig) -> Option<SdkTracerProvider> {
    if !config.enabled {
        info!("OpenTelemetry tracing is disabled");
        return None;
    }

    info!(
        endpoint = %config.otlp_endpoint,
        service = %config.service_name,
        sampling_ratio = config.sampling_ratio,
        "Initializing OpenTelemetry tracing"
    );

    // Create sampler based on sampling ratio
    let sampler = if config.sampling_ratio >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sampling_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sampling_ratio)
    };

    // Build the OTLP trace pipeline using the new_pipeline API
    let trace_config = opentelemetry_sdk::trace::Config::default()
        .with_sampler(sampler)
        .with_resource(Resource::new(vec![
            opentelemetry::KeyValue::new("service.name", config.service_name.clone()),
        ]));

    let provider = match opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&config.otlp_endpoint),
        )
        .with_trace_config(trace_config)
        .install_batch(opentelemetry_sdk::runtime::Tokio)
    {
        Ok(provider) => provider,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create OTLP tracer provider");
            return None;
        }
    };

    // Get tracer from provider
    let tracer = provider.tracer("avalon");

    // Create tracing-opentelemetry layer
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Get current subscriber and add telemetry layer
    // Note: This assumes tracing-subscriber is already initialized
    // We create a new layer that can be added to existing subscriber
    let _ = tracing_subscriber::registry()
        .with(telemetry_layer.with_filter(tracing_subscriber::filter::LevelFilter::INFO))
        .try_init();

    info!("OpenTelemetry tracing initialized successfully");
    Some(provider)
}

/// Shutdown OpenTelemetry and flush pending traces
pub fn shutdown_telemetry(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider {
        info!("Shutting down OpenTelemetry tracing");
        if let Err(e) = provider.shutdown() {
            tracing::error!(error = %e, "Error shutting down tracer provider");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_telemetry() {
        let config = TracingConfig::default();
        assert!(!config.enabled);

        let provider = init_telemetry(&config);
        assert!(provider.is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = TracingConfig::default();
        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "avalon");
        assert_eq!(config.sampling_ratio, 1.0);
    }
}
