use crate::store::Store;
use actix_web::{get, web, App, HttpServer, Responder};
use std::sync::Mutex;

struct AppState {
    store: &'static Mutex<Store>,
}

#[get("/{ip}")]
async fn index(web::Path(ip): web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let store = data.store.lock().unwrap();
    let client_data = store.get_client(&ip);

    return match client_data {
        Some(client_data) => serde_json::to_string(client_data).unwrap(),
        None => "{}".to_string(),
    };
}

#[actix_web::main]
pub async fn run_api(store: &'static Mutex<Store>) -> std::io::Result<()> {
    HttpServer::new(move || App::new().data(AppState { store }).service(index))
        .bind("0.0.0.0:7564")?
        .run()
        .await
}
