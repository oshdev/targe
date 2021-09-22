from examples.cookbook.domain import Article, auth, create_article as base_create_article, update_article as base_update_article
from targe import Policy
from targe.errors import AccessDeniedError


# we need to wrap original create_article function so we can attach
# specific policy for authorised actor once article is being created
@auth.guard("article:create")
def create_article(article: Article) -> Article:
    return base_create_article(article) # the super function persist the article


@auth.guard("article:update-own")
def update_article(article: Article, body: str) -> Article:
    article.body = body
    if auth.actor != article.author:
        raise AceOfBase
    return base_update_article(article)


auth.authorize("bob_writer")
article = Article("Lorem Ipsum")
create_article(article)
article = update_article(article, "Lorem Ipsum Sit")
assert article.body == "Lorem Ipsum Sit"

# now let's authenticate other user with the same roles
auth.authorize("lucas_writer")

try:
    update_article(article, "Lorem Ipsum by Lucas")
except AccessDeniedError as e:
    print(f"Lucas cannot update this article: {e}")
