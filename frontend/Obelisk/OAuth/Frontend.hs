{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

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
  , SupportsOAuth
    -- * Implementation details (probably should not be exported here at all - use with care.)
  , StoreOAuth (..)
  , retrieveCode
  , doAuthorize
  , retrieveToken
  ) where

import Control.Lens
import Control.Monad ((<=<))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Dependent.Sum (DSum ((:=>)))
import Data.Functor.Identity (Identity (..))
import Data.Functor.Identity (Identity)
import Data.Functor.Sum (Sum (..))
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified GHCJS.DOM as DOM
import qualified GHCJS.DOM.Window as Window
import Language.Javascript.JSaddle (MonadJSM)
import Obelisk.Route (Encoder, PageName, R)
import Reflex

import Obelisk.OAuth.Config (OAuthConfig (..), OAuthConfigPublic, OAuthProvider, getOAuthConfigPublic)
import Obelisk.OAuth.Error (OAuthError (..))
import Obelisk.OAuth.Frontend.Internal (makeReflexLenses, tagOnPostBuild)
import Obelisk.OAuth.Frontend.Storage
import Obelisk.OAuth.Request (authorizationRequestHref)
import Obelisk.OAuth.Route (OAuthRoute (..), AccessToken (..), RedirectUriParams (..))
import Obelisk.OAuth.State (OAuthState, genOAuthState)


data OAuthFrontendConfig provider t = OAuthFrontendConfig
  { _oAuthFrontendConfig_authorize :: Event t (AuthorizationRequest provider)
    -- ^ Initiate authorization. This will forward the user to the
    --   authorization provider/server - thus after triggering this event the user will
    --   leave the application. Make sure you to save any important data!
  , _oAuthFrontendConfig_route     :: Dynamic t (Maybe (R OAuthRoute))
    -- ^ Get route updates that are relevant to OAuth.
  }
  deriving Generic


data OAuthFrontend provider t = OAuthFrontend
  { _oAuthFrontend_authorized :: Event t (Either OAuthError (provider, AccessToken))
    -- ^ Event gets triggered after authorization is completed, with either an
    -- error or the token to be used for API requests.
  }
  deriving Generic


type SupportsOAuth t m =
  ( Reflex t, MonadIO m, MonadHold t m, MonadJSM m, PostBuild t m
  , PerformEvent t m , MonadJSM (Performable m)
  , Requester t m, Request m ~ OAuthRequest, Response m ~ DSum OAuthRequest Identity
  )


-- | Make an `OAuthFrontend` provided with the needed configuration.
--
--   The browser's session storage is used for keeping track of the OAuth
--   state. The storage key `show $ StoreOAuth_State
--   _oAuthConfig_provider` is used for storing this state.
makeOAuthFrontend
  :: (SupportsOAuth t m, OAuthProvider provider)
  => OAuthConfig provider
  -> OAuthFrontendConfig t
  -> m (OAuthFrontend t)
makeOAuthFrontend sCfg cfg = do
  onErrParams <- retrieveCode sCfg (_oAuthFrontendConfig_route cfg) $ _oAuthFrontendConfig_authorize cfg
  let (onErr, onParams) = fanEither onErrParams
  eToken <- retrieveToken sCfg getToken onParams
  pure $ OAuthFrontend $ leftmost
    [ Left <$> onErr
    , eToken
    ]


-- | Takes care of issuing the initial authorization request and handling the
--   code response.
--
--   State will be properly generated and checked.
retrieveCode
  :: forall t m r a. (SupportsOAuth t m, OAuthProvider provider)
  => Encoder Identity Identity (R (Sum r a)) PageName
  -> OAuthConfigPublic r
  -> OAuthFrontendConfig t
  -> m (Event t (Either OAuthError (provider, RedirectUriParams)))
retrieveCode sCfg (OAuthFrontendConfig onAuth route) = do

    onReqState <- storeStateRequest <$> onAuth
    performEvent_ $ doAuthorize sCfg <$> onReqState

    onRoute <- fmapMaybe id <$> tagOnPostBuild route

    let
      (onErr, onParams) = fanEither $ getParams <$> onRoute

    onStoreResp <-
      requesting $ OAuthRequest_LoadState . oAuthProviderId . fst <$> onParams

    onMStoredState = fmapMaybe id . ffor onStoreResp $ \case
      OAuthRequest_LoadState provId :=> Identity mState -> Just (provId, mState)
      _ -> Nothing

    onParamsStored :: Event t ((provider, RedirectUriParams), Maybe OAuthState)
      <- getReqResp
          (oAuthProviderId . _authorizationRequest_provider . fst)
          onParams
          onMStoredState

    -- Clean up after ourselves:
    requesting_ $ OAuthRequest_RemoveState . oAuthProviderId . fst . fst <$> onParamsStored

    pure $ leftmost
      [ Left <$> onErr
      , uncurry checkState <$> onParamsStored
      ]

  where
    checkState _ Nothing = Left OAuthError_NoSessionState
    checkState ps@(_, RedirectUriParams c new) (Just old) = if new == old
      then Right ps
      else Left OAuthError_InvalidState

    getParams :: R OAuthRoute -> Either OAuthError (provider, RedirectUriParams)
    getParams = \case
      OAuthRoute_TransmitCode :=> Identity (providerId, Just pars) ->
        (, pars) <$> oAuthProviderFromIdErr providerId
      OAuthRoute_TransmitCode :=> Identity Nothing ->
        Left OAuthError_MissingCodeState


-- | Get an `OAuthCode` and make sure it is stored.
storeStateOnRequest
  :: forall t provider
  . (Reflex t, MonadHold t m, MonadFix m, OAuthProvider provider)
  => Event t AuthorizationRequest provider
  -> m (Event t (AuthorizationRequest provider, OAuthState))
storeStateOnRequest onReq = do

    unsavedCode <- performEvent $ genOAuthState <$ onReq

    r <- requesting $ OAuthRequest_StoreState providerId <$> unsavedCode

    let onResp <- fmapMaybe id . ffor r $ \case
      OAuthRequest_StoreState provId storedState :=> Identity () -> Just (provId, storedState)
      _ -> Nothing

    getReqResp
      (oAuthProviderId . _authorizationRequest_provider)
      onReq
      onResp


-- | Build request uri and forward user to authorization server.
--
doAuthorize
  :: (MonadIO m, MonadJSM m, OAuthProvider provider)
  => OAuthConfigPublic r
  -> (AuthorizationRequest provider, OAuthState)
  -> m ()
doAuthorize sCfg (req, oState) = do

  let reqUri = authorizationRequestHref sCfg req oState

  w <- DOM.currentWindowUnchecked

  Window.open w (Just reqUri) (Just ("_self" :: Text)) (Nothing :: Maybe Text)


-- | Retrieves access token based on redirect values.
--
--   And updates localstorage accordingly.
retrieveToken
  :: SupportsOAuth t m
  => OAuthConfig provider
  -> Event t (provider, RedirectUriParams)
  -> m (Event t (Either OAuthError (provider, AccessToken)))
retrieveToken sCfg getToken onErrParams = do
    let
      (onErr, onParams) = fanEither onErrParams
      mkReq (p, ps) = OAuthRequest_Backend $ OAuthBackendRequest_GetToken (oAuthProviderId p) ps

    (onDirectToken, onParamsReq) <- ffor onParams $ \ps@(provider, RedirectUriParams code state) ->
      let
        rType = _providerConfig_responseType . _oAuthConfig_provider $ provider
      in
        case rType of
          AuthorizationResponseType_Token -> Left (provider, AccessToken . unOAuthCode $ code)
          AuthorizationResponseType_Code  -> Right ps

    eTokenRsp <- requesting $ mkReq <$> onParamsReq
    let
      eToken = fmapMaybe id $ ffor eTokenRsp $ \case
        OAuthRequest_Backend (OAuthBackendRequest_GetToken provId _) :=> Identity errToken ->
          Just $ (,) <$> oAuthProviderFromIdErr provId <*> errToken
        _ ->
          Nothing

    pure $ leftmost
      [ Left <$> onErr
      , Right <$> onDirectToken
      , eToken
      ]


-- | Get a response munched together with it's corresponding request.
--
--   TODO: What to do with multiple identical requests?
getReqResp
  :: (Eq reqId, Ord reqId)
  => (req -> reqId)
  -> Event t req
  -> Event t (reqId, resp)
  -> Event t (req, resp)
getReqResp getReqId onReq onResp = mdo

    reqs <- foldDyn id Map.empty $ mergeWith (.) $
      [ ffor onResp $
          \(reqId, _) -> Map.delete reqId

      , ffor onReq insertReq
      ]

    -- Handle coincidence of request and response properly:
    pure $ fmapMaybe id $ alignWith buildResponse onReq $ attach (current reqs) onResp

  where
    insertReq r = Map.insert (getReqId r) r

    buildResponse = \case
      This _ -> Nothing
      That (cReqs, (reqId, res)) -> (, res) <$> Map.lookup reqId cReqs
      These req (cReqs, res) ->
        buildResponse $ That (insertReq req cReqs, res)
