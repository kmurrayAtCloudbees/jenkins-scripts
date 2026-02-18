import jenkins.model.Jenkins
import hudson.model.ItemGroup
import hudson.model.Job

// ======== CONFIGURE THESE ========
String folderPath = "MyFolder/SubFolder"   // e.g. "TeamA/LegacyApps"; use "" to start at the root
String comment    = "Archived"             // text to prepend to disabled jobs' descriptions
// =================================

def j = Jenkins.instance
def root = (folderPath?.trim()) ? j.getItemByFullName(folderPath) : j

if (!(root instanceof ItemGroup)) {
  println "ERROR: '${folderPath}' not found or not a folder."
  return
}

// Detect if description already starts with the comment (avoid double-prepend)
def commentRegex = "^\\s*" + java.util.regex.Pattern.quote(comment) + "\\b.*"

int scanned = 0
int disabledSeen = 0
int updated = 0

def walk
walk = { item ->
  if (item instanceof ItemGroup) {
    item.items.each { child -> walk(child) }
    return
  }
  if (item instanceof Job) {
    scanned++

    // Some job types may not implement isDisabled(); check safely
    boolean isDisabled = item.metaClass.respondsTo(item, "isDisabled") ? item.isDisabled() : false
    if (!isDisabled) return

    disabledSeen++

    String oldDesc = item.getDescription() ?: ""
    if (!(oldDesc ==~ commentRegex)) {
      String newDesc = oldDesc ? "${comment} ${oldDesc}" : comment
      item.setDescription(newDesc)
      item.save()
      println "Updated DISABLED job: ${item.fullName}"
      updated++
    }
  }
}

walk(root)
println ""
println "Scanned jobs: ${scanned}"
println "Disabled jobs found: ${disabledSeen}"
println "Updated: ${updated}"
