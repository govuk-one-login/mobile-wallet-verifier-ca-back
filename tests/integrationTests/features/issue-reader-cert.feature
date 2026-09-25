Feature: Issue reader certificate service

  Scenario: Request with a missing CSR is rejected
    Given I generate an issue reader cert request without a CSR
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 400 response
    And the response body indicates a missing CSR

  Scenario: Request without an App Check JWT and a valid CSR returns a 200 response
    Given I generate an issue reader cert request without an App Check JWT and a valid CSR
    When I submit the request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 200 OK response
