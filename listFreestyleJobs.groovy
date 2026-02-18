Jenkins.instance.getAllItems(hudson.model.FreeStyleProject).each {it ->
    println it.fullName;
}
