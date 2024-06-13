use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage,
};

use actix_web_lab::middleware::Next;

use super::{api_response, expiration::validation};

pub async fn authentication_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> std::result::Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    match validation(&req).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.call(req).await.map_err(|_| {
                actix_web::Error::from(api_response::ApiResponse::new(
                    401,
                    "Unauthorized".to_string(),
                ))
            })
        }
        Err(err) => std::result::Result::Err(actix_web::Error::from(
            api_response::ApiResponse::new(500, err),
        )),
    }
}
