using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace JWT
{
    public partial class JWT : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // JWT token to validate with rsa256 public key
            string jwtToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtb3JwaGxpbmciLCJhdWQiOiJvcmdhbml6YXRpb25zIGF1dGhvcml6YXRpb24gY29kZSIsImV4cCI6MTcyNjY0NTQ2NiwianRpIjoiZmI1M2ZkNjctMmExNS00MzQ5LTk1N2YtNDllNWM4ZTY4YmViIiwiaW5mIjp7ImxldmVsIjoyLCJuYXRpb25hbF9pZCI6IjAwNzk2ODE5ODAiLCJwaG9uZV9udW1iZXIiOiIwOTEyMjg1MDk3NCIsImZpcnN0X25hbWUiOiLYs9it2LEiLCJsYXN0X25hbWUiOiLZgdiq2K3ZiiDYrti32YrYqNin2YYiLCJzb2xhcl9iaXJ0aF9kYXRlIjoiMTM2NTA2MjYifX0.XOH3IAk4gNXIOBnoQrKkktwZsinRd7tNQNmmpzDhnNGWO6KD3gXradm0bjxhqk0RHoAIMTGi6Xqz98VWKTNRwutJ9o6fkADVNhkDIjsZ818sEGid7kJAushja4s0hfuee1__umU7K7a12q-G26jT7xcI3Sf_Tb0Aeg1y0z5iLLkfGeLmecNuikMn5do7uk54vOCvN5Ubp1ZKSAXxiUk_bw3Cxv5C6MOPg2zIy_cUJmp-4FGvFacWAYQWxud8LPljbH2BqLbk42n4veAbLndY7PXumWbDf9o5pnmsJyA8_NIVMmHTZuMSa-z0Nelxb6M50AHR3CgDM1_EB15_RCfS2A";

            string pemFilePath = Server.MapPath("~/publickey.pem");

            try
            {
                // Load RSA public key from PEM file using BouncyCastle
                RSA rsa = LoadRsaPublicKeyFromPem(pemFilePath);

                // Define validation parameters
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = "morphling",
                    ValidateAudience = true,
                    ValidAudience = "organizations authorization code",
                    ValidateLifetime = false, // if you want to Ensure that token is not expired set True
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa),
                };

                SecurityToken validatedToken;
                var handler = new JwtSecurityTokenHandler();

                // Validate the JWT token
                ClaimsPrincipal claimsPrincipal = handler.ValidateToken(jwtToken, validationParameters, out validatedToken);
                // Extract the "inf" claim
                var jwt = validatedToken as JwtSecurityToken;
                var infClaim = jwt.Payload["inf"];



                if (infClaim != null)
                {
                    if (infClaim is JsonElement infElement)
                    {
                        // Extract each value from the JsonElement
                        int level = infElement.GetProperty("level").GetInt32();
                        string nationalId = infElement.GetProperty("national_id").GetString();
                        string phoneNumber = infElement.GetProperty("phone_number").GetString();
                        string firstName = infElement.GetProperty("first_name").GetString();
                        string lastName = infElement.GetProperty("last_name").GetString();
                        string solarBirthDate = infElement.GetProperty("solar_birth_date").GetString();
                        Response.Write(level + "<br>");
                        Response.Write(nationalId + "<br>");
                        Response.Write(phoneNumber + "<br>");
                        Response.Write(firstName + "<br>");
                        Response.Write(lastName + "<br>");
                        Response.Write(solarBirthDate + "<br>");
                    }
                }
                else
                {
                    Response.Write("The 'inf' key is not present in the token.");
                }
            }
            catch (FileNotFoundException)
            {
                Response.Write("Public key PEM file not found.");
            }
            catch (SecurityTokenException ex)
            {
                Response.Write($"Token validation failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                Response.Write($"An error occurred: {ex.Message}");
            }
        }

        // Helper method to load RSA public key using BouncyCastle
        private RSA LoadRsaPublicKeyFromPem(string pemFilePath)
        {
            using (var reader = new StreamReader(pemFilePath))
            {
                PemReader pemReader = new PemReader(reader);
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)pemReader.ReadObject();
                RSA rsa = RSA.Create();

                // Convert BouncyCastle's RSA key to .NET's RSAParameters
                RSAParameters rsaParameters = new RSAParameters
                {
                    Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                    Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
                };

                // Import the key parameters into the RSA object
                rsa.ImportParameters(rsaParameters);
                return rsa;
            }
        }
    }
}