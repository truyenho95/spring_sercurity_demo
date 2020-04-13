package com.truyenhln.spring_sercurity.sercurity;

public enum ApplicationUserPermission {

    STUDENT_WRITE("student:write"),
    STUDENT_READ("student:read"),
    COURSE_WRITE("course:write"),
    COURSE_READ("course:read");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }

}
