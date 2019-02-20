{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
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
{-# LANGUAGE UndecidableInstances #-}
{-| Random OAuthState.

Description: Random OAuth state to prevent CSRF attacks.
See: <https://tools.ietf.org/html/rfc6749#section-10.12 CSRF> This module only
exports the abstract `OAuthState` and a secure way to generate an `OAuthState`
value. If you need more control, consider "Obelisk.OAuth.State.Internal",
but make sure you are using values that are not guessable by an attacker.
-}
module Obelisk.OAuth.State
  ( -- * Safe interface for handling `OAuthState` values.
    OAuthState
  , genOAuthState
  , oAuthStateAsText
    -- * You are leaving safe territory, use with care.
  , unsafeMkOAuthState
  ) where

import Obelisk.OAuth.State.Internal
