from functools import wraps
from typing import Any, Callable, Union, Dict, Tuple

from .actor import Actor, ActorProvider
from .audit import AuditLog, AuditStore, InMemoryAuditStore
from .errors import AccessDeniedError, InvalidReferenceError, UnauthorizedError, AuthSessionError
from .utils import resolve_reference

OnGuardFunction = Callable[[Actor, str, str], bool]


class Auth:
    def __init__(self, actor_provider: ActorProvider, audit_store: AuditStore = None, on_guard: OnGuardFunction = None):
        self.actor_provider = actor_provider
        self.audit_store = audit_store if audit_store is not None else InMemoryAuditStore()
        self._actor: Actor = None  # type: ignore
        self._on_guard: OnGuardFunction = on_guard

    def init(self, actor_id: str) -> Actor:
        self._actor = self.actor_provider.get_actor(actor_id)
        if not isinstance(self._actor, Actor):
            raise AuthSessionError.for_invalid_actor(actor_id)

        return self._actor

    @property
    def actor(self) -> Actor:
        return self._actor

    def guard(self, scope: str, ref: Union[str, Callable] = "*") -> Callable:
        def _decorator(function: Callable) -> Any:
            @wraps(function)
            def _decorated(*args, **kwargs) -> Any:
                if self.actor is None:
                    raise UnauthorizedError.for_missing_actor()

                self._assert_and_audit(function, kwargs, args, scope, ref)

                return function(*args, **kwargs)

            return _decorated

        return _decorator

    def guard_after(self, scope: str, ref: Union[str, Callable] = "*") -> Callable:
        def _decorator(function: Callable) -> Any:
            @wraps(function)
            def _decorated(*args, **kwargs) -> Any:
                if self.actor is None:
                    raise UnauthorizedError.for_missing_actor()

                result = function(*args, **kwargs)
                kwargs["return"] = result
                self._assert_and_audit(function, kwargs, args, scope, ref)

                return result

            return _decorated

        return _decorator

    def is_allowed(self, scope: str, reference: str) -> bool:
        allowed = self.actor.is_allowed(scope, reference)
        if not allowed and self._on_guard is not None:
            allowed = self._on_guard(self.actor, scope, reference)
        return allowed

    def _assert_and_audit(self, function: Any, kwargs: Dict[str, Any], args: Tuple[Any], scope: str, ref: Union[str, Callable]) -> None:
        resolved_reference = self._resolve_reference(ref, function, kwargs, args)
        audit_entry = AuditLog(self.actor.actor_id, scope, resolved_reference)

        if not self.is_allowed(scope, resolved_reference):
            self.audit_store.log(audit_entry)
            raise AccessDeniedError(
                f"Access denied to referenced resource:`#{resolved_reference}` on scope:`{scope}`"
            )

        audit_entry.mark_succeed()
        self.audit_store.log(audit_entry)

    @staticmethod
    def _resolve_reference(ref: Union[str, Callable], function: Any, kwargs, args) -> str:
        all_kwargs = (
            {**kwargs, **dict(zip(function.__code__.co_varnames, args))}
            if hasattr(function, "__code__")
            else kwargs
        )

        resolved_reference = "*"
        if callable(ref):
            resolved_reference = ref(all_kwargs)
        elif ref != "*":
            try:
                resolved_reference = resolve_reference(all_kwargs, ref)
            except (AttributeError, KeyError) as error:
                raise InvalidReferenceError.for_unresolved_reference(ref, function) from error

        return resolved_reference
