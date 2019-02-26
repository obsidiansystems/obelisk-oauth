{-# LANGUAGE ConstraintKinds        #-}
{-# LANGUAGE DeriveGeneric          #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs                  #-}
{-# LANGUAGE KindSignatures         #-}
{-# LANGUAGE LambdaCase             #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE RankNTypes             #-}
{-# LANGUAGE ScopedTypeVariables    #-}
{-# LANGUAGE StandaloneDeriving     #-}
{-# LANGUAGE TemplateHaskell        #-}
{-# LANGUAGE TypeApplications       #-}

{-| Reflex component for handling `OAuth` oAuthFrontend.

-}
module Obelisk.OAuth.Frontend
  ( -- * Basic interface
    OAuthFrontendConfig (..)
  , HasOAuthFrontendConfig (..)
  , OAuthFrontend (..)
  , HasOAuthFrontend (..)
  , TokenGetter
  , makeOAuthFrontendExeCfg
  , makeOAuthFrontend
    -- * Needed constraints
  , OAuthConstraints
    -- * Implementation details (probably should not be exported here at all - use with care.)
  , StoreOAuth (..)
  , retrieveCode
  , doAuthorize
  , retrieveToken
  ) where

import           Control.Lens
import           Control.Monad                   ((<=<))
import           Control.Monad.IO.Class          (MonadIO, liftIO)
import           Data.Dependent.Sum              (DSum ((:=>)))
import           Data.Functor.Identity           (Identity (..))
import           Data.Functor.Identity           (Identity)
import           Data.Functor.Sum                (Sum (..))
import           Data.Text                       (Text)
import qualified GHCJS.DOM                       as DOM
import qualified GHCJS.DOM.Window                as Window
import           Language.Javascript.JSaddle     (MonadJSM)
import           Obelisk.Route                   (Encoder, PageName, R)
import           Reflex

import           Obelisk.OAuth.Config            (OAuthConfig (..),
                                                  OAuthConfigPublic,
                                                  OAuthProvider,
                                                  getOAuthConfigPublic)
import           Obelisk.OAuth.Error             (OAuthError (..))
import           Obelisk.OAuth.Frontend.Internal (makeReflexLenses,
                                                  tagOnPostBuild)
import           Obelisk.OAuth.Frontend.Storage
import           Obelisk.OAuth.Request           (authorizationRequestHref)
import           Obelisk.OAuth.Route             (OAuthRoute (..),
                                                  OAuthToken (..),
                                                  RedirectUriParams (..))
import           Obelisk.OAuth.State             (OAuthState, genOAuthState)


data OAuthFrontendConfig t = OAuthFrontendConfig
  { _oAuthFrontendConfig_authorize :: Event t ()
    -- ^ Initiate authorization. Initiate this to get a valid access token.
  , _oAuthFrontendConfig_route     :: Dynamic t (Maybe (R OAuthRoute))
    -- ^ Get route updates that are relevant to OAuth.
  }

makeReflexLenses ''OAuthFrontendConfig


data OAuthFrontend t = OAuthFrontend
  { _oAuthFrontend_authorized :: Dynamic t (Maybe (Either OAuthError OAuthToken))
    -- ^ When a authorized, this `Dynamic` will hold the needed access token.
    --   Nothing when not yet authorized, else error or actual token.
  }

makeReflexLenses ''OAuthFrontend


type OAuthConstraints t m =
  ( Reflex t, MonadIO m, MonadHold t m, MonadJSM m, PostBuild t m
  , PerformEvent t m , MonadJSM (Performable m)
  )

data StoreOAuth a where
  -- State that gets stored to session storage:
  StoreOAuth_State :: StoreOAuth OAuthState
  -- Access token that gets stored to local storage:
  StoreOAuth_Token :: StoreOAuth OAuthToken

deriving instance Show (StoreOAuth a)

-- | Function for asking the backend for the actual access token.
type TokenGetter m = RedirectUriParams -> m (Either OAuthError OAuthToken)


-- | Make an `OAuthFrontend` by reading `OAuthConfig` by means of `getOAuthConfigPublic`.
--
--   TODO: We probably want to get rid of this function/ change type signature
--   a bit. As we'd like to encourage the user to provide a config generation
--   function based on `getOAuthConfigPublic` with user values already
--   provided, which can then be used both in frontend and backend. We also
--   might want to consider moving more values into the config. (Ideally we
--   would just not need some of those all together.)
makeOAuthFrontendExeCfg
  :: OAuthConstraints t m
  => OAuthProvider
  -> Encoder Identity Identity (R (Sum r a)) PageName
  -> Maybe (r (R OAuthRoute))
  -> TokenGetter (Performable m)
  -> OAuthFrontendConfig t
  -> m (OAuthFrontend t)
makeOAuthFrontendExeCfg provider enc redirectUri getToken cfg = do
  sCfg <- getOAuthConfigPublic provider redirectUri
  makeOAuthFrontend enc sCfg getToken cfg


-- | Make an `OAuthFrontend` provided with the needed configuration.
makeOAuthFrontend
  :: OAuthConstraints t m
  => Encoder Identity Identity (R (Sum r a)) PageName
  -> OAuthConfigPublic r
  -> TokenGetter (Performable m)
  -> OAuthFrontendConfig t
  -> m (OAuthFrontend t)
makeOAuthFrontend enc sCfg getToken cfg = do
  onErrParams <- retrieveCode enc sCfg (_oAuthFrontendConfig_route cfg) $ _oAuthFrontendConfig_authorize cfg
  eToken <- retrieveToken sCfg getToken onErrParams
  pure $ OAuthFrontend eToken


-- | Takes care of issuing the initial authorization request and handling the
--   code response.
--
--   State will be properly generated and checked.
retrieveCode
  :: forall t m r a. OAuthConstraints t m
  => Encoder Identity Identity (R (Sum r a)) PageName
  -> OAuthConfigPublic r
  -> Dynamic t (Maybe (R OAuthRoute))
  -> Event t ()
  -> m (Event t (Either OAuthError RedirectUriParams))
retrieveCode enc sCfg route onAuth = do
    performEvent_ $ doAuthorize enc sCfg <$ onAuth

    onRoute <- tagOnPostBuild route
    mOldState <- getItemStorage sessionStorage StoreOAuth_State
    let
      onParamsErr = fmapMaybe (fmap (checkState mOldState =<<) . getParams) onRoute
    performEvent_ $ removeItemStorage sessionStorage StoreOAuth_State <$ onParamsErr
    pure onParamsErr

  where
    checkState Nothing _ = Left OAuthError_NoSessionState
    checkState (Just old) ps@(RedirectUriParams c new) = if new == old
      then Right ps
      else Left OAuthError_InvalidState

    getParams :: Maybe (R OAuthRoute) -> Maybe (Either OAuthError RedirectUriParams)
    getParams = \case
      Just (OAuthRoute_TransmitCode :=> Identity (Just p))  -> Just $ Right p
      Just (OAuthRoute_TransmitCode :=> Identity Nothing) -> Just $ Left OAuthError_MissingCodeState
      _ -> Nothing


-- | Build request uri and forward user to authorization server.
--
--   Also creates and stores the OAuth state in session storage.
doAuthorize
  :: (MonadIO m, MonadJSM m)
  => Encoder Identity Identity (R (Sum r a)) PageName
  -> OAuthConfigPublic r
  -> m ()
doAuthorize enc sCfg = do
  let
    provider = _oAuthConfig_provider sCfg
    uri = _oAuthConfig_providerUri sCfg
    clientId = _oAuthConfig_clientId sCfg
  oState <- genOAuthState
  setItemStorage sessionStorage StoreOAuth_State oState

  let
    reqUri = authorizationRequestHref enc sCfg oState
  w <- DOM.currentWindowUnchecked
  Window.open w (Just reqUri) (Just ("_self" :: Text)) (Nothing :: Maybe Text)
  pure ()


-- | Retrieves access token based on redirect values.
--
--   And updates localstorage accordingly.
retrieveToken
  :: OAuthConstraints t m
  => OAuthConfigPublic r
  -> TokenGetter (Performable m)
  -> Event t (Either OAuthError RedirectUriParams)
  -> m (Dynamic t (Maybe (Either OAuthError OAuthToken)))
retrieveToken sCfg getToken onErrParams = do
    let
      (onErr, onParams) = fanEither onErrParams

    eToken <- performEvent $ getToken <$> onParams

    mToken <- getItemStorage localStorage StoreOAuth_Token

    let
      onNewToken = leftmost [ Left <$> onErr, eToken ]

    performEvent_ $
      setItemStorage localStorage StoreOAuth_Token <$> fmapMaybe (^? _Right) onNewToken
    holdDyn (fmap Right mToken) . fmap Just $ onNewToken
