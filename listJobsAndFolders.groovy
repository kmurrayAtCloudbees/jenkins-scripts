Jenkins.instance.getAllItems(AbstractItem.class).each {
    println it.fullName + " - " + it.class
};
