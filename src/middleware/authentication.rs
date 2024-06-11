use std::future::{ready, Ready};

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::{future::LocalBoxFuture, FutureExt};

use super::expiration::validator;

pub struct Authentication;

impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>; // update here
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware { service }))
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>; // update here
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Do something with the request here
        let validation_res = validator(&req);
        if validation_res.is_err() {
            let http_res = HttpResponse::Unauthorized().finish();
            let (http_req, _) = req.into_parts();
            let res = ServiceResponse::new(http_req, http_res);
            // Map to R type
            return (async move { Ok(res.map_into_right_body()) }).boxed_local();
        } else if let Ok(claims) = validation_res {
            req.extensions_mut().insert(claims);
        }

        // Continue with the next middleware / handler
        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            // Map to L type
            Ok(res.map_into_left_body())
        })
    }
}
