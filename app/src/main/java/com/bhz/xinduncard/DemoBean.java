package com.bhz.xinduncard;

/**
 * @author dmrfcoder
 * @date 2019/2/14
 */

public class DemoBean {
    private String name;
    private long age;
    private boolean boy;

    public DemoBean(String name, long age, boolean boy) {
        this.name = name;
        this.age = age;
        this.boy = boy;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public boolean isBoy() {
        return boy;
    }

    public void setBoy(boolean boy) {
        this.boy = boy;
    }
}
