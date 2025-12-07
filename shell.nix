{
  pkgs ? import <nixpkgs> { },
}:

(pkgs.buildFHSEnv {
  name = "auth-server-dev";
  targetPkgs =
    pkgs: with pkgs; [
      gcc
    ];
  runScript = "bun run start";
}).env
