using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecureApiApp.settings;

var builder = WebApplication.CreateBuilder(args);

// Configuração do JWT
var key = Encoding.ASCII.GetBytes("65a8e27d8879283831b664bd8b7f0ad4");
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

// Adicionar serviços do Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configuração do CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost",
        policy =>
        {
            policy.WithOrigins("http://localhost:3000") // Permitir apenas o domínio exato
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });

    options.AddPolicy("AllowAll",
        policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});

var app = builder.Build();

// Configurar o pipeline de requisições
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseMiddleware<HeaderValidationMiddleware>();
}

app.UseHttpsRedirection();

// Adicionar o middleware CORS
app.UseCors("AllowLocalhost"); // Ou "AllowAll", dependendo do ambiente

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
