resource "aws_apigatewayv2_api" "main" {
  name          = "auth2fa-app"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "dev" {
  api_id = aws_apigatewayv2_api.main.id

  name        = "dev"
  auto_deploy = true
}

