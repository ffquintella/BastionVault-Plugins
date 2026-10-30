Feature: SQL browser grants are enforced on every statement

  The vault authorizes each statement; the plugin runs nothing it refused.
  Run against a throwaway PostgreSQL container: `make test-dbms`.

  Background:
    Given a PostgreSQL database with a canary table

  Scenario: A select-only share cannot update
    Given a caller holding "sql_select"
    And an open SQL session
    When the caller runs "UPDATE public.canary SET v = 'changed'"
    Then the statement is refused naming "sql_update"
    And the canary table is unchanged

  Scenario: Revoking a share takes effect on the next statement
    Given a caller holding "sql_select"
    And an open SQL session
    When the caller runs "SELECT v FROM public.canary"
    Then the statement returns 1 row
    When the share is revoked
    And the caller runs "SELECT v FROM public.canary"
    Then the statement is refused naming "sql_select"

  Scenario: Export without sql_export is refused
    Given a caller holding "sql_select"
    And an open SQL session
    When the caller exports "SELECT * FROM public.t" as "csv"
    Then the export is refused naming "sql_export"
    And the audit log records a refused "dbms.export"

  Scenario: A script with one refused statement runs nothing
    Given a caller holding "sql_select, sql_insert, sql_script"
    And an open SQL session
    When the caller runs the script
      """
      INSERT INTO public.t (id, name) VALUES (41, 'a');
      DELETE FROM public.canary;
      SELECT 1
      """
    Then the script is refused naming statement 2 and "sql_delete"
    And no row with id 41 exists
    And the canary table is unchanged

  Scenario: classifier-only sessions are flagged in audit
    Given a caller holding "sql_select" on a classifier-only resource
    When the caller opens a SQL session
    Then the audit log records "dbms.session.open" with enforcement "classifier-only"
