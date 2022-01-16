package com.github.andylke.demo.foo;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class FooDemoScheduler {

  private static final Logger LOGGER = LoggerFactory.getLogger(FooDemoScheduler.class);

  @Scheduled(initialDelay = 1000, fixedDelay = 10000)
  public void runDemo() {

    final String[] values = {"a", "b", "c"};

    ExecutorService executorService = Executors.newFixedThreadPool(3);
    final CompletableFuture<?>[] futures =
        Stream.of(values)
            .map(
                (value) -> {
                  CompletableFuture<Foo> future =
                      CompletableFuture.supplyAsync(
                          () -> {
                            Foo foo = new Foo(value);
                            LOGGER.info("creating foo=[{}] with value=[{}]", foo, value);
                            try {
                              Thread.sleep(2000);
                            } catch (InterruptedException e) {
                              e.printStackTrace();
                            }
                            if ("b".equalsIgnoreCase(value)) {
                              throw new RuntimeException("Cannot be 'b'");
                            }
                            return foo;
                          },
                          executorService);
                  future.whenComplete(
                      (foo, e) -> {
                        if (e != null) {
                          LOGGER.info("exception value=[{}]", value);
                        } else {
                          LOGGER.info("completed foo=[{}] with value=[{}]", foo, value);
                        }
                      });
                  return future;
                })
            .toArray(size -> new CompletableFuture<?>[size]);

    LOGGER.info("waiting for completion");
    try {
      CompletableFuture.allOf(futures).join();
      LOGGER.info("all completed");
    } catch (CompletionException e) {
      LOGGER.info("exception occured {}", e.getMessage());
    }
  }
}
