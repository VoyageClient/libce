final: prev: {
  olm-gcc-cmake = prev.gccStdenv.mkDerivation {
    name = "olm_gcc_cmake";

    src = ./..;

    nativeBuildInputs = [ prev.cmake ];
    doCheck = true;
    checkPhase = ''
      (cd tests && ctest . -j $NIX_BUILD_CORES)
    '';
  };

  olm-clang-cmake = prev.clangStdenv.mkDerivation {
    name = "olm_clang_cmake";

    src = ./..;

    nativeBuildInputs = [ prev.cmake ];

    doCheck = true;
    checkPhase = ''
      (cd tests && ctest . -j $NIX_BUILD_CORES)
    '';
  };

  olm-gcc-make = prev.gccStdenv.mkDerivation {
    name = "olm";

    src = ./..;

    doCheck = true;
    makeFlags = [ "PREFIX=$out" ];
  };

}
