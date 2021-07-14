import * as path from "path";
import { test } from "tap";

import * as dockerFile from "../../../lib/dockerfile";

const getDockerfileFixture = (folder: string) =>
  path.join(__dirname, "../../fixtures/dockerfiles", folder, "Dockerfile");

test("Dockerfile not supplied", async (t) => {
  t.equal(
    await dockerFile.readDockerfileAndAnalyse(),
    undefined,
    "returns undefined",
  );
});

test("Dockerfile not found", async (t) => {
  await t.rejects(
    () => dockerFile.readDockerfileAndAnalyse("missing/Dockerfile"),
    undefined,
    "rejects with",
  );
});

test("Analyses dockerfiles", async (t) => {
  const examples = [
    {
      description: "a simple Dockerfile",
      fixture: "simple",
      expected: {
        baseImage: "ubuntu:bionic",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "a multi-stage Dockerfile",
      fixture: "multi-stage",
      expected: {
        baseImage: "alpine:latest",
        dockerfilePackages: {
          "ca-certificates": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        dockerfileLayers: {
          "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        error: undefined,
      },
    },
    {
      description: "a multi-stage Dockerfile with nested stages name referral",
      fixture: "multi-stage-as",
      expected: {
        baseImage: "alpine:latest",
        dockerfilePackages: {
          "ca-certificates": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        dockerfileLayers: {
          "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        error: undefined,
      },
    },
    {
      description: "a multi-stage Dockerfile with args",
      fixture: "multi-stage-with-args",
      expected: {
        baseImage: "node:6-slim",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "a from-scratch Dockerfile",
      fixture: "from-scratch",
      expected: {
        baseImage: "scratch",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "an empty Dockerfile",
      fixture: "empty",
      expected: {
        baseImage: null,
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: {
          code: "BASE_IMAGE_NAME_NOT_FOUND",
        },
      },
    },
    {
      description: "an invalid Dockerfile",
      fixture: "invalid",
      expected: {
        baseImage: null,
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: {
          code: "BASE_IMAGE_NAME_NOT_FOUND",
        },
      },
    },
    {
      description: "a Dockerfile with multiple ARGs",
      fixture: "with-args",
      expected: {
        baseImage: "node:dubnium",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "a Dockerfile with multiple ARGs no curly braces",
      fixture: "with-args-nobraces",
      expected: {
        baseImage: "node:dubnium",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "a Dockerfile with multiple ARGs and multiple occurrences",
      fixture: "with-args-occurences",
      expected: {
        baseImage: "test:test-1",
        dockerfilePackages: {},
        dockerfileLayers: {},
        error: undefined,
      },
    },
    {
      description: "a Dockerfile with ARG for package",
      fixture: "with-args-package",
      expected: {
        baseImage: "ruby:2.5-alpine",
        dockerfilePackages: {
          bash: {
            instruction:
              "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
          },
          nodejs: {
            instruction:
              "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
          },
        },
        dockerfileLayers: {
          UlVOIGFwayB1cGRhdGUgJiYgYXBrIHVwZ3JhZGUgJiYgYXBrIGFkZCAtLXVwZGF0ZSAtLW5vLWNhY2hlIG5vZGVqcyBiYXNo: {
            instruction:
              "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
          },
        },
        error: undefined,
      },
    },
    {
      description: "a Dockerfile with an installation instruction",
      fixture: "with-installation-instruction",
      expected: {
        baseImage: "ubuntu:bionic",
        dockerfileLayers: {
          UlVOIGFwdC1nZXQgaW5zdGFsbCBjdXJs: {
            instruction: "RUN apt-get install curl",
          },
        },
        dockerfilePackages: {
          curl: {
            instruction: "RUN apt-get install curl",
          },
        },
        error: undefined,
      },
    },
    {
      description: "multi stage Dockerfile with lowercase instructions",
      fixture: "multi-stage-lowercase",
      expected: {
        baseImage: "alpine:latest",
        dockerfilePackages: {
          "ca-certificates": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        dockerfileLayers: {
          "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
            instruction: "RUN apk --no-cache add ca-certificates",
          },
        },
        error: undefined,
      },
    },
  ];
  for (const example of examples) {
    await t.test(example.description, async (t) => {
      const pathToDockerfile = getDockerfileFixture(example.fixture);
      const actual = await dockerFile.readDockerfileAndAnalyse(
        pathToDockerfile,
      );
      t.same(actual, example.expected, "returns unexpected result");
    });
  }
});
