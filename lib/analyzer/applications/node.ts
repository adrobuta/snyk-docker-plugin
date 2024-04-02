import { legacy } from "@snyk/dep-graph";
import * as resolveNodeDeps from 'snyk-resolve-deps';
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import { DepGraphFact, TestedFilesFact } from "../../facts";
import { groupFilesByDirectory, persistAppNodeModules, cleanupAppNodeModules } from "./node-modules-utils";
import { AppDepsScanResultWithoutTarget, FilePathToContent , FilesByDir } from "./types";
import * as path from "path";

const asTree = require('snyk-tree');

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
  lockType: lockFileParser.LockfileType;
}

export async function nodeFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  /**
   * TODO: Add support for Yarn workspaces!
   * https://github.com/snyk/nodejs-lockfile-parser/blob/af8ba81930e950156b539281ecf41c1bc63dacf4/test/lib/yarn-workflows.test.ts#L7-L17
   *
   * When building the ScanResult ensure the workspace is stored in scanResult.identity.args:
   * args: {
   *   rootWorkspace: <path-of-workspace>,
   * };
   */

  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const manifestFilePairs = findManifestLockPairsInSameDirectory(fileNamesGroupedByDirectory);

  if (manifestFilePairs.length === 0) {
    return depGraphFromNodeModules(filePathToContent, fileNamesGroupedByDirectory)
  } else {
    return depGraphFromManifestFiles(filePathToContent, manifestFilePairs)
  }
  return [];
}

async function depGraphFromNodeModules(
  filePathToContent: FilePathToContent,
  fileNamesGroupedByDirectory: FilesByDir
): Promise<AppDepsScanResultWithoutTarget[]> 
{
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const [appRootPath, appRootDir] = await persistAppNodeModules(filePathToContent, fileNamesGroupedByDirectory);

  resolveNodeDeps(appRootDir, {dev: true }).then(function (tree) {
    console.log(asTree(tree));
  }).catch(function (error) {
    // error is usually limited to unknown directory
    console.log(error.stack);
    process.exit(1);
  });

  cleanupAppNodeModules(appRootPath);
  return scanResults;
}

async function depGraphFromManifestFiles(
  filePathToContent: FilePathToContent,
  manifestFilePairs: ManifestLockPathPair[]
): Promise<AppDepsScanResultWithoutTarget[]> 
{
  const scanResults: AppDepsScanResultWithoutTarget[] = [];
  const shouldIncludeDevDependencies = false;
  const shouldBeStrictForManifestAndLockfileOutOfSync = false;

  for (const pathPair of manifestFilePairs) {
    // TODO: initially generate as DepGraph
    const parserResult = await lockFileParser.buildDepTree(
      filePathToContent[pathPair.manifest],
      filePathToContent[pathPair.lock],
      shouldIncludeDevDependencies,
      pathPair.lockType,
      shouldBeStrictForManifestAndLockfileOutOfSync,
      // Don't provide a default manifest file name, prefer the parser to infer it.
    );

    const strippedLabelsParserResult = stripUndefinedLabels(parserResult);
    const depGraph = await legacy.depTreeToGraph(
      strippedLabelsParserResult,
      pathPair.lockType,
    );

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph,
    };
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: [path.basename(pathPair.manifest), path.basename(pathPair.lock)],
    };
    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: pathPair.manifest,
      },
    });
  }
  return scanResults;
}

function findManifestLockPairsInSameDirectory(
  fileNamesGroupedByDirectory: FilesByDir,
): ManifestLockPathPair[] {
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
    if (directoryPath.includes("node_modules")) {
      continue;
    }
    const filesInDirectory = fileNamesGroupedByDirectory[directoryPath];
    if (filesInDirectory.length !== 2) {
      // either a missing file or too many files, ignore
      continue;
    }

    const hasPackageJson = filesInDirectory.includes("package.json");
    const hasPackageLockJson = filesInDirectory.includes("package-lock.json");
    const hasYarnLock = filesInDirectory.includes("yarn.lock");

    if (hasPackageJson && hasPackageLockJson) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "package-lock.json"),
        lockType: lockFileParser.LockfileType.npm,
      });
      continue;
    }

    if (hasPackageJson && hasYarnLock) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "package.json"),
        lock: path.join(directoryPath, "yarn.lock"),
        lockType: lockFileParser.LockfileType.yarn,
      });
      continue;
    }
  }

  return manifestLockPathPairs;
}

function stripUndefinedLabels(
  parserResult: lockFileParser.PkgTree,
): lockFileParser.PkgTree {
  const optionalLabels = parserResult.labels;
  const mandatoryLabels: Record<string, string> = {};
  if (optionalLabels) {
    for (const currentLabelName of Object.keys(optionalLabels)) {
      if (optionalLabels[currentLabelName] !== undefined) {
        mandatoryLabels[currentLabelName] = optionalLabels[currentLabelName]!;
      }
    }
  }
  const parserResultWithProperLabels = Object.assign({}, parserResult, {
    labels: mandatoryLabels,
  });
  return parserResultWithProperLabels;
}