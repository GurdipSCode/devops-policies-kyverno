import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.nodeJS
import jetbrains.buildServer.configs.kotlin.buildSteps.powerShell
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.vcs.GitVcsRoot

/*
The settings script is an entry point for defining a TeamCity
project hierarchy. The script should contain a single call to the
project() function with a Project instance or an init function as
an argument.

VcsRoots, BuildTypes, Templates, and subprojects can be
registered inside the project using the vcsRoot(), buildType(),
template(), and subProject() methods respectively.

To debug settings scripts in command-line, run the

    mvnDebug org.jetbrains.teamcity:teamcity-configs-maven-plugin:generate

command and attach your debugger to the port 8000.

To debug in IntelliJ Idea, open the 'Maven Projects' tool window (View
-> Tool Windows -> Maven Projects), find the generate task node
(Plugins -> teamcity-configs -> teamcity-configs:generate), the
'Debug' option is available in the context menu for the task.
*/

version = "2025.11"

project {

    vcsRoot(HttpsGithubComGurdipSCodeDevopsPoliciesKubernetesRefsHeadsMain1)

    buildType(Build)
}

object Build : BuildType({
    name = "Build"

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        nodeJS {
            id = "nodejs_runner"
            shellScript = "npm ci"
        }
        powerShell {
            name = "Run yamllint"
            id = "Run_yamllint"
            scriptMode = script {
                content = """yamllint -c .yamllint.yml .\policies\"""
            }
        }
        script {
            name = "Validate Kyverno files"
            id = "Validate_Kyverno_files"
            scriptContent = """
                # Validate all policy files
                for policy_file in ${'$'}(find policies -name "*.yaml" -type f); do
                    echo "Validating: ${'$'}policy_file"
                    kyverno validate "${'$'}policy_file"
                done
            """.trimIndent()
        }
    }
})

object HttpsGithubComGurdipSCodeDevopsPoliciesKubernetesRefsHeadsMain1 : GitVcsRoot({
    name = "https://github.com/GurdipSCode/devops-policies-kubernetes#refs/heads/main (1)"
    url = "https://github.com/GurdipSCode/devops-policies-kubernetes"
    branch = "refs/heads/main"
    branchSpec = "refs/heads/*"
    authMethod = token {
        userName = "oauth2"
        tokenId = "tc_token_id:CID_1cdf9f800d9426cda64cdf247762a135:1:0fa30d61-bfbb-40a5-a196-1e5519d5a440"
    }
    param("tokenType", "refreshable")
})
