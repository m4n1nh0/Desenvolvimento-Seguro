namespace SecureApiApp.settings
{
    public class HeaderValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public HeaderValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var headers = context.Request.Headers;

            // Exemplo de validação e sanitização
            if (headers.ContainsKey("X-Custom-Header"))
            {
                var headerValue = headers["X-Custom-Header"].ToString();
                if (!IsValidHeaderValue(headerValue))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Invalid header value");
                    return;
                }
            }

            await _next(context);
        }

        private bool IsValidHeaderValue(string value)
        {
            // Implementar validação conforme necessário
            return !string.IsNullOrWhiteSpace(value) && value.Length < 100; // Exemplo
        }
    }
}
