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

{-| Internal helper functions I should really put in some package at some point.

-}
module Obelisk.OAuth.Frontend.Internal where

import Reflex

tagOnPostBuild :: PostBuild t m => Dynamic t a -> m (Event t a)
tagOnPostBuild v = do
  onPostBuild <- getPostBuild
  pure $ leftmost [ tagPromptlyDyn v onPostBuild
                  , updated v
                  ]
