defmodule JwksRsa do
  @moduledoc """
  Documentation for JwksRsa.
  """

  import Joken, only: [token: 1, peek_header: 1, rs256: 1]

  @doc """
  Gets the RS256 Joken signer from a jwt

  ## Examples

      iex> JwksRsa.get_joken_signer("xxx.xxxx.xxx")
      %Joken.Signer{jwk: %{...}, jws: %{...}}
  """
  def get_joken_signer(jwt) do
    kid =
      jwt
      |> token
      |> peek_header
      |> Map.get("kid")

    case get_signing_key(kid) do
      {:ok, key} ->
        {:ok, rs256(key)}

      {:error, :not_found} ->
        with {:ok, jwks} <- get_jwks(),
             {:ok, _keys} <- cache_signing_keys(jwks),
             {:ok, key} <- get_signing_key(kid) do
          {:ok, rs256(key)}
        else
          error ->
            error
        end
    end
  end

  @doc """
  Get JWKS from HTTP endpoint.

  ## Examples

      iex> JwksRsa.get_jwks
      {:ok, [
        %{
          "alg" => "RS256",
          "e" => "AQAB",
          "kid" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg",
          "kty" => "RSA",
          "n" => "pAIdKx6i8UR9v7GtRsAgPyk9djKFPbQK2h38q4e5pudI3_Gen-wESwq840E21q2EDjapoiwyPqsdZZnA_WAh_PlQuI9km2dfcDWV_x9XltcVmx9eOuwVEp3d59EKEDHvi-KP7m85sjEu_MLpYX-oKrSrOkXv-EgzavOJtUtfZHoRjUEi_TIh7qK0vragbTJRUW4dAFqrGke3uKnVS3pFmtKdI9Klhs-iYzrzZp_Zzv6tPgYqdoiotPWXapeT1IOAy0HWC0F4Rk6TXeqTck2nr1BimHKCWKjgteIOEf7LrYdFmU1szxCv7nZzN3fL2rRDm8oDRGYJMXfn9DGLCaCg5Q",
          "use" => "sig",
          "x5c" => ["MIIDCzCCAfOgAwIBAgIJVDJ7ZxYVCcpEMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTAeFw0xNzEyMTQxMDUwNTFaFw0zMTA4MjMxMDUwNTFaMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKQCHSseovFEfb+xrUbAID8pPXYyhT20Ctod/KuHuabnSN/xnp/sBEsKvONBNtathA42qaIsMj6rHWWZwP1gIfz5ULiPZJtnX3A1lf8fV5bXFZsfXjrsFRKd3efRChAx74vij+5vObIxLvzC6WF/qCq0qzpF7/hIM2rzibVLX2R6EY1BIv0yIe6itL62oG0yUVFuHQBaqxpHt7ip1Ut6RZrSnSPSpYbPomM682af2c7+rT4GKnaIqLT1l2qXk9SDgMtB1gtBeEZOk13qk3JNp69QYphyglio4LXiDhH+y62HRZlNbM8Qr+52czd3y9q0Q5vKA0RmCTF35/QxiwmgoOUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUulGF04yyVY6gcXTWEv6ajPMLfsQwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAmDed2e64bAPbW9YaukM6iQnBq32/J6lfgF/j9qTTNVxTFnSx1K0dAFfGnyXBjT18+b9OZdIrr7+M9NrA4yeOugxo6ipuJscKZ33F8HpwIKvuRE5ckC5yztCf+/woTqx5z/plkFBiDTLDOGXdaZ6j0I4gHv4aLFpBANLVn/BLC2Ohv4bzoTwb/290Sbs5KLg8QxjidweLbx0fhpTzbaoHH2Tu+BRAYcu3GL1X65Dv8htzvImGOPK21JS65SB53gUCrnih1FoYop5L/gNOmEWhEN5xfTBwYseYrDWB65oJJike1Dh/BwZ7ZKwFXY5AJf3QdSscZ6KoSnm23C9ABkU7N"],
          "x5t" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg"
        }
      ]}

  """
  def get_jwks do
    jwks_uri = Application.get_env(:jwks_rsa, :jwks_uri)

    with {:ok, response} <- HTTPoison.get(jwks_uri),
         {:ok, body} <- Poison.decode(response.body) do
      {:ok, body["keys"]}
    else
      {:error, %HTTPoison.Error{} = _error} ->
        {:error, :failed_fetching_jwks}

      _ ->
        {:error, :failed_parsing_jwks_json}
    end
  end

  @doc """
  Validates then caches signing keys.

  ## Examples

      iex> JwksRsa.cache_signing_keys(jwks)
      {:ok, [
        %{
          "alg" => "RS256",
          "e" => "AQAB",
          "kid" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg",
          "kty" => "RSA",
          "n" => "pAIdKx6i8UR9v7GtRsAgPyk9djKFPbQK2h38q4e5pudI3_Gen-wESwq840E21q2EDjapoiwyPqsdZZnA_WAh_PlQuI9km2dfcDWV_x9XltcVmx9eOuwVEp3d59EKEDHvi-KP7m85sjEu_MLpYX-oKrSrOkXv-EgzavOJtUtfZHoRjUEi_TIh7qK0vragbTJRUW4dAFqrGke3uKnVS3pFmtKdI9Klhs-iYzrzZp_Zzv6tPgYqdoiotPWXapeT1IOAy0HWC0F4Rk6TXeqTck2nr1BimHKCWKjgteIOEf7LrYdFmU1szxCv7nZzN3fL2rRDm8oDRGYJMXfn9DGLCaCg5Q",
          "use" => "sig",
          "x5c" => ["MIIDCzCCAfOgAwIBAgIJVDJ7ZxYVCcpEMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTAeFw0xNzEyMTQxMDUwNTFaFw0zMTA4MjMxMDUwNTFaMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKQCHSseovFEfb+xrUbAID8pPXYyhT20Ctod/KuHuabnSN/xnp/sBEsKvONBNtathA42qaIsMj6rHWWZwP1gIfz5ULiPZJtnX3A1lf8fV5bXFZsfXjrsFRKd3efRChAx74vij+5vObIxLvzC6WF/qCq0qzpF7/hIM2rzibVLX2R6EY1BIv0yIe6itL62oG0yUVFuHQBaqxpHt7ip1Ut6RZrSnSPSpYbPomM682af2c7+rT4GKnaIqLT1l2qXk9SDgMtB1gtBeEZOk13qk3JNp69QYphyglio4LXiDhH+y62HRZlNbM8Qr+52czd3y9q0Q5vKA0RmCTF35/QxiwmgoOUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUulGF04yyVY6gcXTWEv6ajPMLfsQwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAmDed2e64bAPbW9YaukM6iQnBq32/J6lfgF/j9qTTNVxTFnSx1K0dAFfGnyXBjT18+b9OZdIrr7+M9NrA4yeOugxo6ipuJscKZ33F8HpwIKvuRE5ckC5yztCf+/woTqx5z/plkFBiDTLDOGXdaZ6j0I4gHv4aLFpBANLVn/BLC2Ohv4bzoTwb/290Sbs5KLg8QxjidweLbx0fhpTzbaoHH2Tu+BRAYcu3GL1X65Dv8htzvImGOPK21JS65SB53gUCrnih1FoYop5L/gNOmEWhEN5xfTBwYseYrDWB65oJJike1Dh/BwZ7ZKwFXY5AJf3QdSscZ6KoSnm23C9ABkU7N"],
          "x5t" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg"
        }
      ]}
  """
  def cache_signing_keys(jwks) do
    if length(jwks) > 0 do
      signing_keys =
        Enum.filter(jwks, fn k ->
          k["use"] == "sig" && k["kty"] == "RSA" && Map.has_key?(k, "kid") &&
            Map.has_key?(k, "x5c") && Map.has_key?(k, "e") && Map.has_key?(k, "n")
        end)

      if length(signing_keys) > 0 do
        case Cachex.put(:jwks_rsa_cache, "signing_keys", signing_keys) do
          {:ok, true} ->
            {:ok, signing_keys}

          error ->
            error
        end
      else
        {:error, :no_keys}
      end
    else
      {:error, :no_keys}
    end
  end

  @doc """
  Gets a signing key from the cache.

  ## Examples

      iex> JwksRsa.get_signing_key(kid)
      {:ok, %{
          "alg" => "RS256",
          "e" => "AQAB",
          "kid" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg",
          "kty" => "RSA",
          "n" => "pAIdKx6i8UR9v7GtRsAgPyk9djKFPbQK2h38q4e5pudI3_Gen-wESwq840E21q2EDjapoiwyPqsdZZnA_WAh_PlQuI9km2dfcDWV_x9XltcVmx9eOuwVEp3d59EKEDHvi-KP7m85sjEu_MLpYX-oKrSrOkXv-EgzavOJtUtfZHoRjUEi_TIh7qK0vragbTJRUW4dAFqrGke3uKnVS3pFmtKdI9Klhs-iYzrzZp_Zzv6tPgYqdoiotPWXapeT1IOAy0HWC0F4Rk6TXeqTck2nr1BimHKCWKjgteIOEf7LrYdFmU1szxCv7nZzN3fL2rRDm8oDRGYJMXfn9DGLCaCg5Q",
          "use" => "sig",
          "x5c" => ["MIIDCzCCAfOgAwIBAgIJVDJ7ZxYVCcpEMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTAeFw0xNzEyMTQxMDUwNTFaFw0zMTA4MjMxMDUwNTFaMCMxITAfBgNVBAMTGG43ZWR1Y2F0aW9uLmF1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKQCHSseovFEfb+xrUbAID8pPXYyhT20Ctod/KuHuabnSN/xnp/sBEsKvONBNtathA42qaIsMj6rHWWZwP1gIfz5ULiPZJtnX3A1lf8fV5bXFZsfXjrsFRKd3efRChAx74vij+5vObIxLvzC6WF/qCq0qzpF7/hIM2rzibVLX2R6EY1BIv0yIe6itL62oG0yUVFuHQBaqxpHt7ip1Ut6RZrSnSPSpYbPomM682af2c7+rT4GKnaIqLT1l2qXk9SDgMtB1gtBeEZOk13qk3JNp69QYphyglio4LXiDhH+y62HRZlNbM8Qr+52czd3y9q0Q5vKA0RmCTF35/QxiwmgoOUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUulGF04yyVY6gcXTWEv6ajPMLfsQwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAmDed2e64bAPbW9YaukM6iQnBq32/J6lfgF/j9qTTNVxTFnSx1K0dAFfGnyXBjT18+b9OZdIrr7+M9NrA4yeOugxo6ipuJscKZ33F8HpwIKvuRE5ckC5yztCf+/woTqx5z/plkFBiDTLDOGXdaZ6j0I4gHv4aLFpBANLVn/BLC2Ohv4bzoTwb/290Sbs5KLg8QxjidweLbx0fhpTzbaoHH2Tu+BRAYcu3GL1X65Dv8htzvImGOPK21JS65SB53gUCrnih1FoYop5L/gNOmEWhEN5xfTBwYseYrDWB65oJJike1Dh/BwZ7ZKwFXY5AJf3QdSscZ6KoSnm23C9ABkU7N"],
          "x5t" => "RkFGRDQ4OURGQjEwQ0JERTNCMjc3QTRDOTkzNDFBMzlENzA1MTQyNg"
        }
      }
  """
  def get_signing_key(kid) do
    case Cachex.get(:jwks_rsa_cache, "signing_keys") do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, keys} ->
        case Enum.find(keys, &(&1["kid"] == kid)) do
          nil ->
            {:error, :not_found}

          key ->
            {:ok, key}
        end
    end
  end
end
