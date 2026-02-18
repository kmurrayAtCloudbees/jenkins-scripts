import jenkins.model.Jenkins
import com.cloudbees.hudson.plugins.folder.Folder

// ============================================================================
// PARAMETERS
// ============================================================================
def parentFolderPath = "environment_folder"  // Example: "MyOrg/TeamA" or "" for root
def verboseMode = false     // Set to true to print all folder paths
// ============================================================================

def controllerName = Jenkins.instance.getRootUrl() ?: System.getenv('HOSTNAME') ?: "Unknown"

println "=" * 70
println "FOLDER REPLICATION SANITY CHECK"
println "Controller: ${controllerName}"
println "Parent Folder: ${parentFolderPath ?: '(ROOT - Entire Hierarchy)'}"
println "Verbose Mode: ${verboseMode ? 'ENABLED' : 'DISABLED'}"
println "Timestamp: ${new Date()}"
println "=" * 70

// Get starting point - either specific parent folder or root
def startingPoint
def scanScope

if (parentFolderPath) {
    startingPoint = Jenkins.instance.getItemByFullName(parentFolderPath, Folder.class)
    if (!startingPoint) {
        println "\n ERROR: Parent folder '${parentFolderPath}' not found!"
        return
    }
    scanScope = "under '${parentFolderPath}'"
} else {
    startingPoint = Jenkins.instance
    scanScope = "in entire hierarchy"
}

// Collect all folders within scope
def allFolders = []
if (parentFolderPath) {
    // Get all nested folders under the parent
    allFolders = startingPoint.getAllItems(Folder.class)
} else {
    // Get all folders in entire Jenkins instance
    allFolders = Jenkins.instance.getAllItems(Folder.class)
}

println "\nTotal Folders ${scanScope}: ${allFolders.size()}"

// RBAC statistics
def foldersWithRBAC = allFolders.findAll { folder ->
    new File(folder.rootDir, "nectar-rbac.xml").exists()
}.size()
println "Folders with RBAC: ${foldersWithRBAC}"
println "Folders without RBAC: ${allFolders.size() - foldersWithRBAC}"

// Folder depth analysis (relative to parent if specified)
def depthCounts = [:].withDefault { 0 }
allFolders.each { folder ->
    def fullPath = folder.fullName
    def relativePath = parentFolderPath ? fullPath.replaceFirst("^${parentFolderPath}/", "") : fullPath
    def depth = relativePath.split('/').size()
    depthCounts[depth]++
}

println "\n" + "-" * 70
println "FOLDER DISTRIBUTION BY DEPTH LEVEL:"
println "-" * 70
depthCounts.sort().each { depth, count ->
    println "Level ${depth}: ${count} folders"
}

// Direct children of starting point
def directChildren
if (parentFolderPath) {
    directChildren = startingPoint.items.findAll { it instanceof Folder }
} else {
    directChildren = Jenkins.instance.items.findAll { it instanceof Folder }
}

println "\n" + "-" * 70
println "DIRECT CHILD FOLDERS (Level 1 ${scanScope}): ${directChildren.size()}"
println "-" * 70
directChildren.sort { it.name }.each { folder ->
    def rbacMarker = new File(folder.rootDir, "nectar-rbac.xml").exists() ? "[RBAC]" : ""
    def fullPath = folder.fullName
    println "  • ${fullPath} ${rbacMarker}"
}

// VERBOSE MODE: Print all folders with details
if (verboseMode) {
    println "\n" + "=" * 70
    println "VERBOSE OUTPUT: ALL FOLDERS (${allFolders.size()} total)"
    println "=" * 70
    
    def sortedFolders = allFolders.sort { it.fullName }
    sortedFolders.eachWithIndex { folder, index ->
        def rbacMarker = new File(folder.rootDir, "nectar-rbac.xml").exists() ? "[RBAC]" : "[NO RBAC]"
        def fullPath = folder.fullName
        def relativePath = parentFolderPath ? fullPath.replaceFirst("^${parentFolderPath}/", "") : fullPath
        def depth = relativePath.split('/').size()
        
        println "${String.format('%5d', index + 1)}. [L${depth}] ${rbacMarker} ${fullPath}"
        
        // Progress indicator for large lists
        if ((index + 1) % 1000 == 0) {
            println "       ... processed ${index + 1} of ${allFolders.size()} folders ..."
        }
    }
    println "=" * 70
    println "END VERBOSE OUTPUT"
    println "=" * 70
}

println "\n" + "=" * 70
println "SUMMARY FOR COMPARISON:"
println "  Scan Scope: ${scanScope}"
println "  Total Folders: ${allFolders.size()}"
println "  With RBAC: ${foldersWithRBAC}"
println "  Without RBAC: ${allFolders.size() - foldersWithRBAC}"
println "  Direct Children: ${directChildren.size()}"
if (verboseMode) {
    println "  Verbose Mode: ENABLED (all folders listed above)"
}
println "=" * 70