// Copyright 2020 Oxide Computer Company

//! Example use of Dropshot with TLS enabled

use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::ConfigTls;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::RequestContext;
use dropshot::ServerBuilder;
use dropshot::TypedBody;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use std::error::Error;
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::info;
use tracing::{debug, error, info, span, trace, warn, Level};
use tracing_subscriber;

// the `#[tracing::instrument]` attribute creates and enters a span
// every time the instrumented function is called. The span is named after the
// the function or method. Paramaters passed to the function are recorded as fields.
#[tracing::instrument]
pub fn shave(yak: usize) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // this creates an event at the TRACE log level with two fields:
    // - `excitement`, with the key "excitement" and the value "yay!"
    // - `message`, with the key "message" and the value "hello! I'm gonna shave a yak."
    //
    // unlike other fields, `message`'s shorthand initialization is just the string itself.
    trace!(excitement = "yay!", "hello! I'm gonna shave a yak");
    if yak == 3 {
        warn!("could not locate yak");
        return OutOfSpaceError
            .fail()
            .map_err(|source| MissingYakError::OutOfSpace { source })
            .context(MissingYak)
            .map_err(|err| err.into());
    } else {
        trace!("yak shaved successfully");
    }
    Ok(())
}

pub fn shave_all(yaks: usize) -> usize {
    // Constructs a new span named "shaving_yaks" at the INFO level,
    // and a field whose key is "yaks". This is equivalent to writing:
    //
    // let span = span!(Level::INFO, "shaving_yaks", yaks = yaks);
    //
    // local variables (`yaks`) can be used as field values
    // without an assignment, similar to struct initializers.
    let span = span!(Level::INFO, "shaving_yaks", yaks);
    let _enter = span.enter();

    info!("shaving yaks");

    let mut yaks_shaved = 0;
    for yak in 1..=yaks {
        let res = shave(yak);
        debug!(target: "yak_events", yak, shaved = res.is_ok());

        if let Err(ref error) = res {
            // Like spans, events can also use the field initialization shorthand.
            // In this instance, `yak` is the field being initalized.
            error!(yak, error = error.as_ref(), "failed to shave yak");
        } else {
            yaks_shaved += 1;
        }
        trace!(yaks_shaved);
    }

    yaks_shaved
}

// Error types
// Usually you would pick one error handling library to use, but they can be mixed freely
#[derive(Debug, Snafu)]
enum OutOfSpaceError {
    #[snafu(display("out of cash"))]
    OutOfCash,
}

#[derive(Debug, Error)]
enum MissingYakError {
    #[error("out of space")]
    OutOfSpace { source: OutOfSpaceError },
}

#[derive(Debug, Snafu)]
enum YakError {
    #[snafu(display("missing yak"))]
    MissingYak { source: MissingYakError },
}

// This function would not be used in a normal application. It is used to
// generate temporary keys and certificates for the purpose of this demo.
fn generate_keys() -> Result<(NamedTempFile, NamedTempFile), String> {
    let keypair = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| e.to_string())?;
    let cert = keypair.cert.pem();
    let priv_key = keypair.key_pair.serialize_pem();

    let make_temp = || {
        tempfile::Builder::new()
            .prefix("dropshot-https-example-")
            .rand_bytes(5)
            .tempfile()
    };

    let mut cert_file = make_temp().map_err(|_| "failed to create cert_file")?;
    cert_file
        .write(cert.as_bytes())
        .map_err(|_| "failed to write cert_file")?;
    let mut key_file = make_temp().map_err(|_| "failed to create key_file")?;
    key_file
        .write(priv_key.as_bytes())
        .map_err(|_| "failed to write key_file")?;
    Ok((cert_file, key_file))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // install global subscriber configured based on RUST_LOG envvar.
    tracing_subscriber::fmt::init();

    let number_of_yaks = 3;
    // this creates a new event, outside of any spans.
    info!(number_of_yaks, "preparing to shave yaks");

    let number_shaved = yak_shave::shave_all(number_of_yaks);
    info!(
        all_yaks_shaved = number_shaved == number_of_yaks,
        "yak shaving completed."
    );
    // Begin by generating TLS certificates and keys and stuffing them into a
    // TLS configuration.
    let (cert_file, key_file) = generate_keys()?;
    let config_tls = Some(ConfigTls::AsFile {
        cert_file: cert_file.path().to_path_buf(),
        key_file: key_file.path().to_path_buf(),
    });

    // See dropshot/examples/basic.rs for more details on most of these pieces.
    let config_logging = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    };
    let log = config_logging
        .to_logger("example-basic")
        .map_err(|error| format!("failed to create logger: {}", error))?;

    let mut api = ApiDescription::new();
    api.register(example_api_get_counter).unwrap();
    api.register(example_api_put_counter).unwrap();

    let api_context = ExampleContext::new();

    let server = ServerBuilder::new(api, api_context, log)
        // This differs from the basic example: provide the TLS configuration.
        .tls(config_tls)
        .start()
        .map_err(|error| format!("failed to create server: {}", error))?;

    server.await
}

/// Application-specific example context (state shared by handler functions)
struct ExampleContext {
    /// counter that can be manipulated by requests to the HTTP API
    counter: AtomicU64,
}

impl ExampleContext {
    /// Return a new ExampleContext.
    pub fn new() -> ExampleContext {
        ExampleContext {
            counter: AtomicU64::new(0),
        }
    }
}

// HTTP API interface

/// `CounterValue` represents the value of the API's counter, either as the
/// response to a GET request to fetch the counter or as the body of a PUT
/// request to update the counter.
#[derive(Deserialize, Serialize, JsonSchema)]
struct CounterValue {
    counter: u64,
}

/// Fetch the current value of the counter.
#[endpoint {
    method = GET,
    path = "/counter",
}]
async fn example_api_get_counter(
    rqctx: RequestContext<ExampleContext>,
) -> Result<HttpResponseOk<CounterValue>, HttpError> {
    let api_context = rqctx.context();

    Ok(HttpResponseOk(CounterValue {
        counter: api_context.counter.load(Ordering::SeqCst),
    }))
}

/// Update the current value of the counter.  Note that the special value of 10
/// is not allowed (just to demonstrate how to generate an error).
#[endpoint {
    method = PUT,
    path = "/counter",
}]
async fn example_api_put_counter(
    rqctx: RequestContext<ExampleContext>,
    update: TypedBody<CounterValue>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let api_context = rqctx.context();
    let updated_value = update.into_inner();

    if updated_value.counter == 10 {
        Err(HttpError::for_bad_request(
            Some(String::from("BadInput")),
            format!("do not like the number {}", updated_value.counter),
        ))
    } else {
        api_context
            .counter
            .store(updated_value.counter, Ordering::SeqCst);
        Ok(HttpResponseUpdatedNoContent())
    }
}
