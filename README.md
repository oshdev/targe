# Targe
Powerful and flexible authorization library based on policy system (but not limited).


## Installation

With pip:
```
pip install targe
```

or with poetry

```
poetry add targe
```

## Quick start

```python
from targe import Auth, ActorProvider, Actor, Policy
from targe.errors import AccessDeniedError


# This will provide actor for auth mechanism
class MyActorProvider(ActorProvider):
    def get_actor(self, actor_id: str) -> Actor:
        return Actor(actor_id)


# Initialise auth class
auth = Auth(MyActorProvider())

# Retrieves and authorizes actor by its id
auth.authorize("actor_id")


# `auth.guard` decorator assigns auth scope to a function and
# protects it from non-authorized access
@auth.guard(scope="protected")
def protect_this() -> None:
    ...  # code that should be protected by auth


try:
    protect_this()
except AccessDeniedError:
    ...  # this will fail as actor has no access to scope `protected`

auth.actor.policies.append(Policy.allow("protected"))  # add `protected` scope to actor policies
protect_this()  # now this works
```

## Features

### Customisable and flexible policy system
Policy system in **Targe** is not limited to specific keywords like `read`, `write`, `create`, etc. 
Instead it uses scopes, scopes can hold any value that makes sense in your application's domain 
like `eat:salads`. To increase flexibility and control over your domain **Targe** allows for defining references
that can point to specific data in your application.

### Minimal, close to 0 learning curve
If you already have some experience with other `acl` or `authorization` libraries there is 
almost 0 learning curve. In order to start using the library you only need to learn 5 methods:
- `Auth.guard`
- `Auth.guard_after`
- `Policy.allow`
- `Policy.deny`
- `ActorProvider.get_actor`

### Built-in audit log
Everytime guarded function is executed library creates a log entry. This log entries can be persisted
and used later on to understand who, when, how and what has changed within your application.

### Elegant and easy to use interface
You don't have to write complex `if` statements asserting whether user has given role or policy. 
All of that happens automatically in one small `@guard` decorator, which can be attached to 
any function/method within your codebase and easily removed if needed. 

# Usage

## Execution flow

The following diagram is a high level representation of the execution flow:

![execution flow](./docs/execution_flow.png)

When function gets called, instance of `Auth` class is checking whether `actor` is accessible 
(this should happen when `Auth.init` is called). 

If `actor` is not accessible because `Auth.init` was not called `UnauthorizedError` exception is raised. 

When `actor` is present, library will try to resolve `reference` (reference contains a value that points to a piece 
of data stored in your application), reference resolving will happen only in the scenarios when `ref` attribute 
is provided in the `guard` decorator.

Everytime guarded function is being called, library automatically generates audit log, which can be persisted
in database if correct `auth.AuditStore` implementation is provided during `Auth` initialization.

The last step is execution of guarded function.

## Actor
Actor represents authenticated user in your application. Other important characteristics are:
- an actor aggregates permissions and roles
- an actor encapsulates its state and may act upon its change  
- actor knows whether is can access given scope
- actor's id is referenced in audit log  
- actor can be extended further to encapsulate your application logic 

### Creating new actor

```python
from targe import Actor

my_actor = Actor("actor_id")
```

### Assigning policies

```python
from targe import Actor, Policy

my_actor = Actor("actor_id")

# assign policies 
my_actor.policies.append(Policy.allow("articles:update"))
```

### Assigning roles

```python
from targe import Actor, Policy, Role

my_actor = Actor("actor_id")

# simple role
user_manager = Role("user_manager")
user_manager.policies.append(Policy.allow("user:*"))

# assign role
my_actor.roles.append(user_manager)
```

### Providing actor to auth system
By default, auth system does not know who is your actor and what it can do. 

To provide information about your actor, you have to implement `targe.ActorProvider` interface, 
please consider the following example:

```python
from targe import ActorProvider, Actor, Auth


class MyActorProvider(ActorProvider):
    def get_actor(self, actor_id: str) -> Actor:
        ...  # you can query your database or do other relevant task to factory your instance of `targe.Actor`
        return Actor(actor_id)


# now we have to just instantiate auth and pass instance of our ActorProvider implementation
auth = Auth(MyActorProvider())

# The following line will cause auth system to use `MyActorProvider.get_actor` method.
auth.authorize("actor_id")
```

## Policies

**Policy** is an object representing logical rule describing how and what type of information
can be accessed in your application. 
Once policies are created they can ba attached to a role, or a user to ensure fine-grained
access control.

Policies contain `scopes` and `references`. The first ones holds an information how data is 
being accessed within your application (`read`, `write`, `update`, `etc`), 
the latter ones define a rule that might limit accessibility to a single piece of information
or entire group.

The following code example defines a policy that might be used to allow user 
updating articles in specified category (`animals` in this scenario).

```python
from targe import Policy

policy = Policy.allow(scope="articles:update", ref="articles:animals:*")
```

Having policy above we could also specify an article with id of `article_id` within `animals` category 
that should not be updated:

```python
from targe import Policy

policy = Policy.deny("articles:update", "articles:animals:article_id")
```

### Scopes

Scopes can be used to set logical boundaries in your application. These are the boundaries 
in which data is being accessed and/or manipulated. Scope names can contain `:` (namespace separator) 
to improve granularity e.g.: `article:meta:setKeywords`.

Defining policy per scope can be repetitive task, consider the following example:

```python
from targe import Policy

Policy.allow("article:meta:setKeywords")
Policy.allow("article:meta:setVersion")
Policy.allow("article:meta:setCategory")
Policy.allow("article:meta:getKeywords")
Policy.allow("article:meta:getVersion")
Policy.allow("article:meta:getCategory")
...
```

> Note: if no reference is provided in a policy it will fallback to `*` (wildcard). Wildcard matches any reference.
 
In the scenarios like this, `targe` provides pattern matching mechanism, so the above can be simplified to:

```python
from targe import Policy

Policy.allow("article:meta:set*")
Policy.allow("article:meta:get*")
```

`article:meta:set*` will match everything in `articles:meta` namespace that starts with `set` word.

### References

References can be used to identify and/or logically group your data. References are using similar 
mechanism to scopes, which means in policies definition you can take advantage of `:` (namespace separator)
same way like you do it in the scope definition. 

Namespace's elements in reference have no names thus using two namespaces that have different number of sections
but start with the same sequence can have some implications.

Let's have a look how pattern matching will work in this scenario:
```
users:{group}:{id}
               +
               |    When matching reference with pattern `users:group:*`, we can match both
               |    all users within all {sub-groups} and all users within a {group},
               |    so having these two references in our application can cause problems.
               +
users:{group}:{sub-group}:{id}
```

Defining additional namespace element inside your reference can solve the problem, it may follow 
the schema `{resource_type}:{namespace_name}:{logical-group-n}:{logical-group-n+1}:{id}`:

```
users:by_group:{group}:{id}
        +
        |   Because we have additonal namespace element which is unique (`by_group` in the first case and `by_subgroup`
        |   in the second case), we can safely use both references together in our application.
        +
users:by_subgroup:{group}:{sub-group}:{id}
```

> It is recommended to have one schema reference per resource type unless your schema grows large (has many namespace elements).

## Roles

Role is a collection of policies with a unique name. Roles can be also 
used to build Role-based access control (RBAC), which is a simplified mechanism
for regulating access to part of your application based on the roles 
of individual actor.

The following is an example code, where `user_manager` Role is defined, that later on can be used
to grand access for actor to access different scopes:

```python
from targe import Role, Policy

role = Role("user_manager")

# You can also attach policies, it is not needed if you are planning to build
# authorization system based on RBAC
role.policies.append(Policy.allow("user:create"))
role.policies.append(Policy.allow("user:update"))
role.policies.append(Policy.allow("user:delete"))
role.policies.append(Policy.allow("user:read"))
```

> Role names must follow [a-z][a-z0-9_-] pattern. Role name is also its identifier, 
> thus they should be unique across your application.

## Guarding function

Protecting function from unauthorized access is one of the **Targe**'s main objectives.

We can protect function from unauthorized execution in two ways:
- acl based style
- rbac style

Use rbac style in scenarios where you have to just assert if actor has given role, use acl based style in other cases.
ACL based style is not only giving you more control over your resources but also automatically enables audit log. 

### Guarding function - rbac style example

To protect function from unauthorized execution use `Auth.guard(rbac=[...])` decorator with `rbac` argument. The `rbac`
argument accepts list of strings where each string is a role name that is required in to execute annotated function.

> If more than one role is passed in the `rbac` argument, this means actor has to own all the required roles
> to execute annotated function.

```python
from targe import ActorProvider, Actor, Auth
from targe.errors import AccessDeniedError

class MyActorProvider(ActorProvider):
    def get_actor(self, actor_id: str) -> Actor:
        return Actor(actor_id)
    
auth = Auth(MyActorProvider())

auth.authorize("actor_id")

@auth.guard(rbac=["user_manager"])  # Here we use `Auth.guard` decorator to protect `create_user` function
def create_user() -> None:
    ...

try:
    create_user()
except AccessDeniedError:
    print("`create_user` is protected from unauthorized access.")
```

> Keep in mind you can still take advantage of audit log in rbac mode, 
> the only requirement is to provide `scope` argument in `Auth.guard` decorator.

### Guarding function - acl style example

```python
from targe import ActorProvider, Actor, Auth
from targe.errors import AccessDeniedError

class MyActorProvider(ActorProvider):
    def get_actor(self, actor_id: str) -> Actor:
        return Actor(actor_id)
    
auth = Auth(MyActorProvider())

auth.authorize("actor_id")

@auth.guard(scope="user:create") 
def create_user() -> None:
    ...

try:
    create_user()
except AccessDeniedError:
    print("`create_user` is protected from unauthorized access.") 
```

### Overriding function guarding mechanism

You can override default behavior of guard mechanism in scenarios when it denies access to guarded
function. In order to do that pass a callable object to `Auth` initializer, like below:

```python
from targe import ActorProvider, Actor, Auth

class MyActorProvider(ActorProvider):
    def get_actor(self, actor_id: str) -> Actor:
        return Actor(actor_id)
    
def on_guard(actor: Actor, scope: str, reference: str) -> bool:
    if scope == "user:create":
        return True
    
    return False
    
auth = Auth(MyActorProvider(), on_guard=on_guard)
auth.authorize("actor_id")

@auth.guard(scope="user:create") 
def create_user() -> None:
    ...

create_user()
```

Callable object must return `bool` value (`True` in order to allow access, `False` to deny access) and accept three parameters:
- `actor: targe.Actor` - an actor that is currently authorized in the system
- `scope: str` - scope assigned to guarded function
- `reference: str` - resolved reference to currently used resource


## Audit log

Audit log might be useful if you need to track actor's activities in your application.
By default, all actor's actions against guarded functions are automatically recorded and stored
in memory as long as `scope` attribute is provided in the `Auth.guard` decorator. 

> `InMemoryAuditStore` class is a default in-memory implementation of `AuditStore` protocol, which
> is instantiated by `Auth` class if no other implementation is provided.


### AuditLog entry




### Persisting audit log

