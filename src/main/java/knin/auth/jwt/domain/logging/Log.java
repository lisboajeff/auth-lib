package knin.auth.jwt.domain.logging;

/**
 * Pure, zero-dependency logging interface for auth-lib.
 * Completely decoupled from third-party frameworks, allowing any application
 * to plug in its preferred logging mechanism (e.g., JBoss Logging, SLF4J, Log4j, System.out, or a lambda).
 */
@FunctionalInterface
public interface Log {

    void log(String message);

    default void info(String message) {
        log(message);
    }

    default void info(String format, Object... args) {
        log(String.format(format, args));
    }

    default void warn(String message) {
        log(message);
    }

    default void warn(String format, Object... args) {
        log(String.format(format, args));
    }

    default void error(String message, Throwable throwable) {
        log(message + (throwable != null ? ": " + throwable.getMessage() : ""));
    }

    static Log noop() {
        return message -> {};
    }

    static Log systemOut() {
        return System.out::println;
    }

}
