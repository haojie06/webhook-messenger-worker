use serde::Deserialize;
use serde_json::{self, Value};
use wasm_bindgen::JsValue;
use worker::*;

#[derive(Deserialize, Debug)]
struct WebhookRelayRequest {
    pub endpoint: String,
    pub secret: String,
    pub payload: Value,
}

#[event(fetch)]
async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match req.method() {
        Method::Post => {
            let api_key_in_cfg = env
                .var("API_KEY")
                .expect("cannot get API_KEY in env")
                .to_string();
            let api_key_in_req = if let Some(api_key_in_req) =
                req.headers().get("api-key").unwrap_or(Some("".to_string()))
            {
                api_key_in_req
            } else {
                return Response::error("Missing API Key", 401);
            };

            if api_key_in_cfg != api_key_in_req {
                return Response::error("Invalid API Key", 401);
            }
            let relay_req = match req.json::<WebhookRelayRequest>().await {
                Ok(r) => r,
                Err(_) => {
                    return Response::error("Invalid Request Body", 400);
                }
            };

            // send request to target endpoint
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            headers.set("X-Webhook-Secret", &relay_req.secret)?;
            let request = Request::new_with_init(
                &relay_req.endpoint,
                RequestInit::new()
                    .with_method(Method::Post)
                    .with_headers(headers)
                    .with_body(Some(JsValue::from_str(&relay_req.payload.to_string()))),
            )?;
            let mut resp = Fetch::Request(request).send().await?;
            let resp_text = resp.text().await?;
            Response::ok(format!("{}: {}", resp.status_code(), resp_text))
        }
        _ => Response::error("Method not allowed", 405),
    }
}
