package validation

import knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"

func init() {
	registerSourceChecks(knowledge.SourceFriendsOfPHP, upstreamTotalCheck(knowledge.SourceFriendsOfPHP))
}
