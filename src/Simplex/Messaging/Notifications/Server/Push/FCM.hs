{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use newtype instead of data" #-}

-- | Pheme: Firebase Cloud Messaging (HTTP v1) push provider for Android.
--
-- Same privacy model as APNS: the notification carries only data encrypted for the device
-- (nonce + crypto_box with the token's DH secret), never message content or contact data, and
-- is sent as a high-priority *data* message (no visible notification text from the server).
--
-- Credentials: a Google service account JSON file (Firebase Messaging only) whose path is in the
-- environment variable FCM_SERVICE_ACCOUNT_FILE. It is read when the first FCM token is used.
module Simplex.Messaging.Notifications.Server.Push.FCM
  ( FCMPushClientConfig (..),
    defaultFCMPushClientConfig,
    createFCMPushClient,
    fcmPushProviderClient,
  ) where

import Control.Exception (throwIO)
import Control.Logger.Simple
import Control.Monad.Except
import Control.Monad.IO.Class
import Control.Monad.Trans.Except
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA15
import Crypto.Random (ChaChaDRG)
import qualified Crypto.Store.PKCS8 as PK
import Data.Aeson (ToJSON, (.=))
import qualified Data.Aeson as J
import qualified Data.Aeson.Key as JK
import qualified Data.Aeson.TH as JQ
import Data.Bifunctor (first)
import qualified Data.ByteString.Base64.URL as U
import Data.ByteString.Builder (lazyByteString)
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as LB
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock.System
import qualified Data.X509 as X
import qualified Data.X509.CertificateStore as XS
import qualified Network.HTTP.Types as N
import qualified Network.HTTP2.Client as H
import Network.Socket (HostName, ServiceName)
import qualified Simplex.Messaging.Crypto as C
import Simplex.Messaging.Notifications.Protocol
import Simplex.Messaging.Notifications.Server.Push.APNS (PushNotification (..), PushProviderClient, PushProviderError (..))
import Simplex.Messaging.Notifications.Server.Store.Types (NtfTknRec (..))
import Simplex.Messaging.Transport.HTTP2 (HTTP2Body (..))
import Simplex.Messaging.Transport.HTTP2.Client
import Simplex.Messaging.Util (safeDecodeUtf8, tshow)
import System.Environment (getEnv)
import System.X509 (getSystemCertificateStore)
import UnliftIO.STM

data FCMPushClientConfig = FCMPushClientConfig
  { serviceAccountFileEnv :: String,
    -- | FCM data payloads are limited to 4 KB: base64 of 2560 bytes plus JSON fits.
    paddedNtfLength :: Int,
    fcmHost :: HostName,
    oauthHost :: HostName,
    httpsPort :: ServiceName,
    http2cfg :: HTTP2ClientConfig,
    caStoreFile :: FilePath,
    -- | refresh the OAuth access token this many seconds before it expires
    tokenRefreshMargin :: Int64
  }

defaultFCMPushClientConfig :: FCMPushClientConfig
defaultFCMPushClientConfig =
  FCMPushClientConfig
    { serviceAccountFileEnv = "FCM_SERVICE_ACCOUNT_FILE",
      paddedNtfLength = 2560,
      fcmHost = "fcm.googleapis.com",
      oauthHost = "oauth2.googleapis.com",
      httpsPort = "443",
      http2cfg = defaultHTTP2ClientConfig {bufferSize = 16384},
      caStoreFile = "/etc/ssl/cert.pem",
      tokenRefreshMargin = 300
    }

-- | Fields used from the Google service account JSON (other fields are ignored).
data ServiceAccount = ServiceAccount
  { project_id :: Text,
    private_key_id :: Text,
    private_key :: Text,
    client_email :: Text
  }

$(JQ.deriveFromJSON J.defaultOptions ''ServiceAccount)

data OAuthToken = OAuthToken {access_token :: Text, expires_in :: Int64}

$(JQ.deriveFromJSON J.defaultOptions ''OAuthToken)

data FCMPushClient = FCMPushClient
  { fcmClient :: TVar (Maybe HTTP2Client),
    oauthClient :: TVar (Maybe HTTP2Client),
    account :: ServiceAccount,
    signingKey :: RSA.PrivateKey,
    accessToken :: TVar (Maybe (ByteString, Int64)), -- token, expiry (seconds from epoch)
    nonceDrg :: TVar ChaChaDRG,
    fcmCfg :: FCMPushClientConfig
  }

createFCMPushClient :: FCMPushClientConfig -> IO FCMPushClient
createFCMPushClient fcmCfg@FCMPushClientConfig {serviceAccountFileEnv} = do
  file <- getEnv serviceAccountFileEnv
  account@ServiceAccount {private_key} <-
    either (throwIO . userError . ("FCM service account: " <>)) pure . J.eitherDecodeStrict' =<< B.readFile file
  signingKey <- case PK.readKeyFileFromMemory (encodeUtf8 private_key) of
    [PK.Unprotected (X.PrivKeyRSA k)] -> pure k
    _ -> throwIO $ userError "FCM service account: private_key is not an unencrypted RSA PKCS#8 key"
  fcmClient <- newTVarIO Nothing
  oauthClient <- newTVarIO Nothing
  accessToken <- newTVarIO Nothing
  nonceDrg <- C.newRandom
  pure FCMPushClient {fcmClient, oauthClient, account, signingKey, accessToken, nonceDrg, fcmCfg}

-- | Google OAuth 2.0 for service accounts: a JWT signed with RS256, exchanged for an access token.
signedAssertion :: FCMPushClient -> Int64 -> IO ByteString
signedAssertion FCMPushClient {account = ServiceAccount {private_key_id, client_email}, signingKey} now = do
  let hdr = J.object ["alg" .= ("RS256" :: Text), "typ" .= ("JWT" :: Text), "kid" .= private_key_id]
      claims =
        J.object
          [ "iss" .= client_email,
            "scope" .= ("https://www.googleapis.com/auth/firebase.messaging" :: Text),
            "aud" .= ("https://oauth2.googleapis.com/token" :: Text),
            "iat" .= now,
            "exp" .= (now + 3600)
          ]
      signingInput = jwtEncode hdr <> "." <> jwtEncode claims
  RSA15.signSafer (Just SHA256) signingKey signingInput >>= \case
    Right sig -> pure $ signingInput <> "." <> U.encodeUnpadded sig
    Left e -> throwIO . userError $ "FCM JWT signing failed: " <> show e
  where
    jwtEncode :: ToJSON a => a -> ByteString
    jwtEncode = U.encodeUnpadded . LB.toStrict . J.encode

connectHTTPS2 :: FCMPushClientConfig -> HostName -> TVar (Maybe HTTP2Client) -> IO (Either HTTP2ClientError HTTP2Client)
connectHTTPS2 FCMPushClientConfig {httpsPort, http2cfg, caStoreFile} host v =
  readTVarIO v >>= \case
    Just c -> pure $ Right c
    Nothing -> do
      caStore <- XS.readCertificateStore caStoreFile >>= maybe getSystemCertificateStore pure
      r <- getHTTP2Client host httpsPort (Just caStore) http2cfg (atomically $ writeTVar v Nothing)
      case r of
        Right c -> atomically . writeTVar v $ Just c
        Left e -> logError $ "Error connecting to " <> T.pack host <> ": " <> tshow e
      pure r

-- | Cached access token, refreshed shortly before it expires.
getAccessToken :: FCMPushClient -> ExceptT PushProviderError IO ByteString
getAccessToken c@FCMPushClient {accessToken, oauthClient, fcmCfg = cfg@FCMPushClientConfig {oauthHost, tokenRefreshMargin}} = do
  now <- liftIO $ systemSeconds <$> getSystemTime
  liftIO (readTVarIO accessToken) >>= \case
    Just (tkn, expiry) | now < expiry - tokenRefreshMargin -> pure tkn
    _ -> do
      assertion <- liftIO $ signedAssertion c now
      http2 <- ExceptT $ first PPConnection <$> connectHTTPS2 cfg oauthHost oauthClient
      let body = N.renderSimpleQuery False [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion)]
          req = H.requestBuilder N.methodPost "/token" [(N.hContentType, "application/x-www-form-urlencoded")] (lazyByteString $ LB.fromStrict body)
      HTTP2Response {response, respBody = HTTP2Body {bodyHead}} <- ExceptT $ first PPConnection <$> sendRequestDirect http2 req Nothing
      case (H.responseStatus response, J.decodeStrict' bodyHead) of
        (Just s, Just OAuthToken {access_token, expires_in}) | s == N.ok200 -> do
          let tkn = encodeUtf8 access_token
          atomically $ writeTVar accessToken $ Just (tkn, now + expires_in)
          pure tkn
        (s, _) -> do
          logError $ "FCM OAuth error: " <> tshow s <> " " <> safeDecodeUtf8 bodyHead
          throwE $ PPRetryLater "FCM OAuth token"

-- | Data-only message: the app wakes, fetches from the SMP relays and shows its own notification.
fcmData :: NtfTknRec -> C.CbNonce -> Int -> PushNotification -> Either C.CryptoError [(Text, Text)]
fcmData NtfTknRec {tknDhSecret} nonce paddedLen = \case
  PNVerification (NtfRegCode code) -> (\v -> [("nonce", nonceText), ("verification", v)]) <$> encrypt code
  PNMessage pnMessageData -> (\m -> [("nonce", nonceText), ("message", m)]) <$> encrypt (encodePNMessages pnMessageData)
  PNCheckMessages -> Right [("checkMessages", "true")]
  where
    encrypt ntfData = safeDecodeUtf8 . U.encode <$> C.cbEncrypt tknDhSecret nonce ntfData paddedLen
    -- the same text the APNS payload carries for "nonce"
    nonceText = case J.toJSON nonce of
      J.String t -> t
      v -> safeDecodeUtf8 . LB.toStrict $ J.encode v

fcmPushProviderClient :: FCMPushClient -> PushProviderClient
fcmPushProviderClient c@FCMPushClient {fcmClient, nonceDrg, account = ServiceAccount {project_id}, fcmCfg = cfg@FCMPushClientConfig {fcmHost, paddedNtfLength}} tkn@NtfTknRec {token = DeviceToken _ tknStr} pn = do
  nonce <- atomically $ C.randomCbNonce nonceDrg
  dataFields <- liftEither $ first PPCryptoError $ fcmData tkn nonce paddedNtfLength pn
  accessTkn <- getAccessToken c
  http2 <- ExceptT $ first PPConnection <$> connectHTTPS2 cfg fcmHost fcmClient
  let message =
        J.object
          [ "message"
              .= J.object
                [ "token" .= safeDecodeUtf8 tknStr,
                  "android" .= J.object ["priority" .= ("HIGH" :: Text)],
                  "data" .= J.object [JK.fromText k .= v | (k, v) <- dataFields]
                ]
          ]
      path = "/v1/projects/" <> encodeUtf8 project_id <> "/messages:send"
      headers = [(N.hAuthorization, "Bearer " <> accessTkn), (N.hContentType, "application/json")]
      req = H.requestBuilder N.methodPost path headers (lazyByteString $ J.encode message)
  HTTP2Response {response, respBody = HTTP2Body {bodyHead}} <- ExceptT $ first PPConnection <$> sendRequestDirect http2 req Nothing
  let status = H.responseStatus response
      body = safeDecodeUtf8 bodyHead
  if status == Just N.ok200
    then logDebug "FCM response: ok"
    else logWarn $ "FCM error: " <> tshow status <> " " <> T.take 300 body
  result status body
  where
    result :: Maybe N.Status -> Text -> ExceptT PushProviderError IO ()
    result status body
      | status == Just N.ok200 = pure ()
      | status == Just N.notFound404 || "UNREGISTERED" `T.isInfixOf` body = throwE $ PPTokenInvalid NTIRUnregistered
      | status == Just N.badRequest400 && "registration token" `T.isInfixOf` body = throwE $ PPTokenInvalid NTIRBadToken
      | status == Just N.unauthorized401 = do
          -- access token revoked or expired early: drop it, the next attempt gets a new one
          atomically $ writeTVar (accessToken c) Nothing
          throwE $ PPRetryLater "401"
      | status == Just N.forbidden403 = throwE PPPermanentError -- wrong project or Messaging API disabled
      | status `elem` map Just [N.tooManyRequests429, N.internalServerError500, N.serviceUnavailable503] = throwE $ PPRetryLater (tshow status)
      | otherwise = throwE $ PPResponseError status body
