load("@io_bazel_rules_scala//scala:scala.bzl", "scala_binary")

scala_binary (
    name = "BazelApp",
    srcs = glob(["scala/**/*.scala"]),
    main_class = "example.Main",
    deps = [
      "@maven//:javax_xml_bind_jaxb_api",
      "@maven//:org_bouncycastle_bcprov_jdk15on",
      "@maven//:commons_codec_commons_codec",
    ],
)
