Feature: Issue reader certificate service

  Scenario: Valid mock request returns a 200 response
    Given the issue reader certificate API test endpoints are configured
    When I generate a valid mock issue reader certificate request
    And I submit the mock issue reader certificate request to the issue reader cert endpoint
    Then the issue reader cert endpoint returns a 200 happy-path response
