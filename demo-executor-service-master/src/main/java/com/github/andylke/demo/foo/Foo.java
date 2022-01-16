package com.github.andylke.demo.foo;

import org.apache.commons.lang3.builder.ToStringBuilder;

public class Foo {

  private String text;

  public Foo(final String text) {
    this.text = text;
  }

  public Foo() {}

  public String getText() {
    return text;
  }

  public void setText(String text) {
    this.text = text;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this);
  }
}
