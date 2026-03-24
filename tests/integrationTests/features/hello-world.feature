Feature: Hello World

  Scenario: Greeting a user
    Given I have a name "World"
    When I greet the name
    Then the greeting should be "Hello, World!"
