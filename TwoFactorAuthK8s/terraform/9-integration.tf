resource "aws_security_group" "vpc_link" {
  name   = "vpc-link"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_apigatewayv2_vpc_link" "eks" {
  name               = "eks"
  security_group_ids = [aws_security_group.vpc_link.id]
  subnet_ids = [
    aws_subnet.private-eu-central-1a.id,
    aws_subnet.private-eu-central-1b.id
  ]
}

resource "aws_apigatewayv2_integration" "eks" {
  api_id = aws_apigatewayv2_api.main.id

  integration_uri    = "arn:aws:elasticloadbalancing:eu-central-1:830384327934:listener/net/af5ef1825ea54401ab430e71cf36772f/80ac661cfcad356b/a784b73c78fd83b4"
  integration_type   = "HTTP_PROXY"
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.eks.id
}

resource "aws_apigatewayv2_route" "home_page" {
  api_id = aws_apigatewayv2_api.main.id

  route_key = "GET /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.eks.id}"
}

output "hello_base_url" {
  value = aws_apigatewayv2_stage.dev.invoke_url
}
