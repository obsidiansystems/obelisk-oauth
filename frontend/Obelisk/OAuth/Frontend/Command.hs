{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FlexibleContexts #-}
{-| Abstract commands needed by obelisk-oauth for its operation.

    The obelisk-oauth frontend is implemented by means of a Requester who is
    able to execute a simple DSL for sending requests to the backend and
    storing oauth state to some storage, like session storage.

    Find an example interpreter using session storage in this file.
-}
module Obelisk.OAuth.Frontend.Command
  ( -- * Interpreter implementation
    --
    --   you will need to provide an interpreter for the commands in `CommandF`.
    CommandF (..)
    -- * Interface
  , Command
  , command_storeState
  , command_loadState
  , command_removeState
  , command_getToken
  ) where

import Control.Monad.Free (Free (..), liftF, MonadFree (..))

import Obelisk.OAuth.Error (OAuthError (..))
import Obelisk.OAuth.Route (AccessToken (..), RedirectUriParams (..))
import Obelisk.OAuth.State (OAuthState)

-- | Commands for storing state and retrieving the `AccessToken` from the backend.
--
--   The frontend needs to store some random state temporarely for the OAuth
--   handshake to work in a secure way: For authorization the user gets
--   forwarded to the authorization server and then gets redirected back to the
--   application. We need a way for holding onto some state in the meantime. A
--   simple means for implementing those commands is via the browser's session
--   storage.
--
--   The needed provider have an instance of `OAuthProvider`.
data CommandF provider next
  = CommandF_StoreState provider OAuthState next
  -- ^ Store some `OAuthState` to temporal storage
  | CommandF_LoadState provider (Maybe OAuthState -> next)
  -- ^ Load some `OAuthState` from temporal storage
  | CommandF_RemoveState provider next
  -- ^ For good measure: Get rid of it after usage.
  | CommandF_GetToken provider RedirectUriParams (Either OAuthError AccessToken -> next)
  -- ^ After the redirect coming from the authorization server we need a way
  -- for asking the backend to retrieve the actual access token, given the code
  -- we just received. This is so, that the client secret which is needed for
  -- retrieving the token stays private. For providers you are using  the less
  -- secure `AuthorizationResponseType_Token` you can skip the backend
  -- implementation and implement this command by means of
  -- `tokenFromDirectResponse`.
  deriving (Functor)

{- -- Can we re-use an api specification as Free monad? -}
{- newtype CommandF next = -}
{-   forall a. Command (OAuthRequest a) (a -> next) -}

{- interpreter = \case -}
{-   Free (Command req@(Req1 a b c) getNext) -> sendReq req >>= getNext -}

{- commandReq1 :: MonadFree (CommandF provider) m => a -> b -> c -> m r -}
{- commandReq1 a b c = liftF $ Command (Req1 a b c) id -}


command_storeState :: MonadFree (CommandF provider) m => provider -> OAuthState -> m ()
command_storeState p s = liftF $ CommandF_StoreState p s ()

command_loadState :: MonadFree (CommandF provider) m => provider -> m (Maybe OAuthState)
command_loadState p = liftF $ CommandF_LoadState p id

command_removeState :: MonadFree (CommandF provider) m => provider -> m ()
command_removeState p = liftF $ CommandF_RemoveState p ()

command_getToken
  :: MonadFree (CommandF provider) m
  => provider
  -> RedirectUriParams
  -> m (Either OAuthError AccessToken)
command_getToken p pars = liftF $ CommandF_GetToken p pars id

type Command provider = Free (CommandF provider)
