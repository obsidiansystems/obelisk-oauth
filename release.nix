let
  example = import ./example {};
in {
  ghcShell = example.shells.ghc;
  ghcsjsShell = example.shells.ghcjs;
  exe = example.exe;
}
