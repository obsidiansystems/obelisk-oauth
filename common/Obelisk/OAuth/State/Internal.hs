{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{-| Internals of "Obelisk.OAuth.State". Use if you want to provide your own
   `OAuthState` generator, but make sure you are using truly random values!
-}
module Obelisk.OAuth.State.Internal where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.ByteString.Base16 as Base16
import Data.Text (Text)
import qualified Data.Text.Encoding as T
import GHC.Generics (Generic)
import System.Entropy (getEntropy)


-- | Oauth state to prevent CSRF attacks.
newtype OAuthState = OAuthState { unOAuthState :: Text }
  deriving (Generic, Show, Read, Eq, Ord, ToJSON, FromJSON)

-- | Make an `OAuthState` from some Text.
--
--   If you need a brand new `OAuthState` you should use `genOAuthState`. This
--   function is useful for deserialization of server responses for example.
unsafeMkOAuthState :: Text -> OAuthState
unsafeMkOAuthState = OAuthState

-- | Get a `Text` representation of `OAuthState`.
--
--   Useful for serialization/encoding purposes.
oAuthStateAsText :: OAuthState -> Text
oAuthStateAsText = unOAuthState

-- | Generate some truly random `OAuthState`.
--
--   By truly random we mean unguessable by an attacker - e.g. not dependent
--   on some value derived from the current time.
genOAuthState :: MonadIO m => m OAuthState
genOAuthState = liftIO $ do
  -- 20 bytes recommended by RFC: https://tools.ietf.org/html/rfc6749#section-10.10
  OAuthState . T.decodeUtf8 . Base16.encode <$> getEntropy 20
