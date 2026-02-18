Jenkins.instance.getAllItems(AbstractProject.class).each {it ->
    println it.fullName;
}
