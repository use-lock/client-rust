#![cfg(all(feature = "admin", feature = "management", feature = "auth-api"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use lock_client::admin::apis::{configuration::Configuration, realms_api};
use lock_client::management::apis::clients_api;
use serde_json::json;

/// Answers every request and records `METHOD path?query authorization`.
async fn serve(status: u16, body: serde_json::Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(get(
            |State((status, body, seen)): State<(
                u16,
                serde_json::Value,
                Arc<Mutex<Vec<String>>>,
            )>,
             request: Request| async move {
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_owned();
                seen.lock().unwrap().push(format!(
                    "{} {} {authorization}",
                    request.method(),
                    request.uri()
                ));
                (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
            },
        ))
        .with_state((status, body, seen.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

fn config(base: &str) -> Configuration {
    Configuration {
        base_path: format!("{base}/api"),
        oauth_access_token: Some("machine-token".into()),
        ..Configuration::default()
    }
}

fn page() -> serde_json::Value {
    json!({
        "data": [], "links": [],
        "meta": { "current_page": 1, "first_page_url": null, "from": null, "last_page": 1, "last_page_url": null,
                  "next_page_url": null, "path": null, "per_page": 15, "prev_page_url": null, "to": null, "total": 0 }
    })
}

#[tokio::test]
async fn admin_client_sends_the_bearer_token_and_decodes_the_collection() {
    let (url, seen) = serve(200, page()).await;
    let params = realms_api::ListRealmsParams {
        sort: None,
        filter_name: None,
        filter_slug: None,
        filter_domain: None,
        filter_domain_status: None,
        page: Some(2),
        per_page: None,
    };
    let realms = realms_api::list_realms(&config(&url), params)
        .await
        .unwrap();

    assert!(realms.data.is_empty());
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["GET /api/v1/realms?page=2 Bearer machine-token"]
    );
}

#[tokio::test]
async fn errors_are_typed() {
    let (url, _) = serve(
        404,
        json!({ "message": "No query results for model [Realm]." }),
    )
    .await;
    let error = realms_api::get_realm(
        &config(&url),
        realms_api::GetRealmParams {
            realm: "nope".into(),
        },
    )
    .await
    .unwrap_err();

    match error {
        lock_client::admin::apis::Error::ResponseError(response) => {
            assert_eq!(response.status, 404);
            assert!(matches!(
                response.entity,
                Some(realms_api::GetRealmError::Status404(_))
            ));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn management_client_addresses_a_realm() {
    let (url, seen) = serve(200, page()).await;
    let config = lock_client::management::apis::configuration::Configuration {
        base_path: format!("{url}/api"),
        oauth_access_token: Some("t".into()),
        ..Default::default()
    };
    let params = clients_api::ListClientsParams {
        realm: "staging".into(),
        sort: None,
        filter_name: None,
        filter_client_id: None,
        filter_revoked: None,
        filter_token_endpoint_auth_method: None,
        page: None,
        per_page: None,
    };
    let _ = clients_api::list_clients(&config, params).await;
    assert_eq!(
        seen.lock().unwrap()[0],
        "GET /api/v1/realms/staging/clients Bearer t"
    );
}
