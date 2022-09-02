// Generated from ./src/stixpattern/STIXPattern.g4 by ANTLR 4.10.1
// jshint ignore: start
import antlr4 from 'antlr4';
import STIXPatternListener from './STIXPatternListener.js';
const serializedATN = [4,1,54,233,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,
4,2,5,7,5,2,6,7,6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,
2,13,7,13,2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,1,0,1,0,1,0,1,1,1,1,1,
1,1,1,1,1,1,1,5,1,46,8,1,10,1,12,1,49,9,1,1,2,1,2,1,2,1,2,1,2,1,2,5,2,57,
8,2,10,2,12,2,60,9,2,1,3,1,3,1,3,1,3,1,3,1,3,5,3,68,8,3,10,3,12,3,71,9,3,
1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,3,4,82,8,4,1,4,1,4,1,4,1,4,1,4,1,4,5,
4,90,8,4,10,4,12,4,93,9,4,1,5,1,5,1,5,1,5,1,5,1,5,5,5,101,8,5,10,5,12,5,
104,9,5,1,6,1,6,1,6,1,6,1,6,1,6,5,6,112,8,6,10,6,12,6,115,9,6,1,7,1,7,3,
7,119,8,7,1,7,1,7,1,7,1,7,1,7,3,7,126,8,7,1,7,1,7,1,7,1,7,1,7,3,7,133,8,
7,1,7,1,7,1,7,1,7,1,7,3,7,140,8,7,1,7,1,7,1,7,1,7,1,7,3,7,147,8,7,1,7,1,
7,1,7,1,7,1,7,3,7,154,8,7,1,7,1,7,1,7,1,7,1,7,3,7,161,8,7,1,7,1,7,1,7,1,
7,1,7,1,7,1,7,1,7,1,7,3,7,172,8,7,1,8,1,8,1,8,1,8,1,8,1,9,1,9,1,9,1,9,1,
10,1,10,1,10,1,10,1,11,1,11,1,11,1,11,3,11,191,8,11,1,12,1,12,1,13,1,13,
1,14,1,14,1,14,1,14,1,14,1,14,3,14,203,8,14,1,14,1,14,5,14,207,8,14,10,14,
12,14,210,9,14,1,15,1,15,1,15,1,15,1,15,1,15,5,15,218,8,15,10,15,12,15,221,
9,15,1,15,1,15,3,15,225,8,15,1,16,1,16,3,16,229,8,16,1,17,1,17,1,17,0,7,
2,4,6,8,10,12,28,18,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,0,7,
1,0,31,32,1,0,33,36,2,0,2,2,4,4,1,0,29,30,2,0,7,7,29,29,2,0,1,2,50,50,2,
0,1,7,9,9,244,0,36,1,0,0,0,2,39,1,0,0,0,4,50,1,0,0,0,6,61,1,0,0,0,8,81,1,
0,0,0,10,94,1,0,0,0,12,105,1,0,0,0,14,171,1,0,0,0,16,173,1,0,0,0,18,178,
1,0,0,0,20,182,1,0,0,0,22,186,1,0,0,0,24,192,1,0,0,0,26,194,1,0,0,0,28,202,
1,0,0,0,30,224,1,0,0,0,32,228,1,0,0,0,34,230,1,0,0,0,36,37,3,2,1,0,37,38,
5,0,0,1,38,1,1,0,0,0,39,40,6,1,-1,0,40,41,3,4,2,0,41,47,1,0,0,0,42,43,10,
2,0,0,43,44,5,13,0,0,44,46,3,2,1,3,45,42,1,0,0,0,46,49,1,0,0,0,47,45,1,0,
0,0,47,48,1,0,0,0,48,3,1,0,0,0,49,47,1,0,0,0,50,51,6,2,-1,0,51,52,3,6,3,
0,52,58,1,0,0,0,53,54,10,2,0,0,54,55,5,11,0,0,55,57,3,4,2,3,56,53,1,0,0,
0,57,60,1,0,0,0,58,56,1,0,0,0,58,59,1,0,0,0,59,5,1,0,0,0,60,58,1,0,0,0,61,
62,6,3,-1,0,62,63,3,8,4,0,63,69,1,0,0,0,64,65,10,2,0,0,65,66,5,10,0,0,66,
68,3,6,3,3,67,64,1,0,0,0,68,71,1,0,0,0,69,67,1,0,0,0,69,70,1,0,0,0,70,7,
1,0,0,0,71,69,1,0,0,0,72,73,6,4,-1,0,73,74,5,44,0,0,74,75,3,10,5,0,75,76,
5,43,0,0,76,82,1,0,0,0,77,78,5,42,0,0,78,79,3,2,1,0,79,80,5,41,0,0,80,82,
1,0,0,0,81,72,1,0,0,0,81,77,1,0,0,0,82,91,1,0,0,0,83,84,10,3,0,0,84,90,3,
16,8,0,85,86,10,2,0,0,86,90,3,18,9,0,87,88,10,1,0,0,88,90,3,20,10,0,89,83,
1,0,0,0,89,85,1,0,0,0,89,87,1,0,0,0,90,93,1,0,0,0,91,89,1,0,0,0,91,92,1,
0,0,0,92,9,1,0,0,0,93,91,1,0,0,0,94,95,6,5,-1,0,95,96,3,12,6,0,96,102,1,
0,0,0,97,98,10,2,0,0,98,99,5,11,0,0,99,101,3,10,5,3,100,97,1,0,0,0,101,104,
1,0,0,0,102,100,1,0,0,0,102,103,1,0,0,0,103,11,1,0,0,0,104,102,1,0,0,0,105,
106,6,6,-1,0,106,107,3,14,7,0,107,113,1,0,0,0,108,109,10,2,0,0,109,110,5,
10,0,0,110,112,3,12,6,3,111,108,1,0,0,0,112,115,1,0,0,0,113,111,1,0,0,0,
113,114,1,0,0,0,114,13,1,0,0,0,115,113,1,0,0,0,116,118,3,22,11,0,117,119,
5,12,0,0,118,117,1,0,0,0,118,119,1,0,0,0,119,120,1,0,0,0,120,121,7,0,0,0,
121,122,3,32,16,0,122,172,1,0,0,0,123,125,3,22,11,0,124,126,5,12,0,0,125,
124,1,0,0,0,125,126,1,0,0,0,126,127,1,0,0,0,127,128,7,1,0,0,128,129,3,34,
17,0,129,172,1,0,0,0,130,132,3,22,11,0,131,133,5,12,0,0,132,131,1,0,0,0,
132,133,1,0,0,0,133,134,1,0,0,0,134,135,5,20,0,0,135,136,3,30,15,0,136,172,
1,0,0,0,137,139,3,22,11,0,138,140,5,12,0,0,139,138,1,0,0,0,139,140,1,0,0,
0,140,141,1,0,0,0,141,142,5,14,0,0,142,143,5,7,0,0,143,172,1,0,0,0,144,146,
3,22,11,0,145,147,5,12,0,0,146,145,1,0,0,0,146,147,1,0,0,0,147,148,1,0,0,
0,148,149,5,15,0,0,149,150,5,7,0,0,150,172,1,0,0,0,151,153,3,22,11,0,152,
154,5,12,0,0,153,152,1,0,0,0,153,154,1,0,0,0,154,155,1,0,0,0,155,156,5,17,
0,0,156,157,5,7,0,0,157,172,1,0,0,0,158,160,3,22,11,0,159,161,5,12,0,0,160,
159,1,0,0,0,160,161,1,0,0,0,161,162,1,0,0,0,162,163,5,16,0,0,163,164,5,7,
0,0,164,172,1,0,0,0,165,166,5,42,0,0,166,167,3,10,5,0,167,168,5,41,0,0,168,
172,1,0,0,0,169,170,5,18,0,0,170,172,3,22,11,0,171,116,1,0,0,0,171,123,1,
0,0,0,171,130,1,0,0,0,171,137,1,0,0,0,171,144,1,0,0,0,171,151,1,0,0,0,171,
158,1,0,0,0,171,165,1,0,0,0,171,169,1,0,0,0,172,15,1,0,0,0,173,174,5,21,
0,0,174,175,5,9,0,0,175,176,5,22,0,0,176,177,5,9,0,0,177,17,1,0,0,0,178,
179,5,26,0,0,179,180,7,2,0,0,180,181,5,23,0,0,181,19,1,0,0,0,182,183,5,27,
0,0,183,184,5,2,0,0,184,185,5,28,0,0,185,21,1,0,0,0,186,187,3,24,12,0,187,
188,5,38,0,0,188,190,3,26,13,0,189,191,3,28,14,0,190,189,1,0,0,0,190,191,
1,0,0,0,191,23,1,0,0,0,192,193,7,3,0,0,193,25,1,0,0,0,194,195,7,4,0,0,195,
27,1,0,0,0,196,197,6,14,-1,0,197,198,5,39,0,0,198,203,7,4,0,0,199,200,5,
44,0,0,200,201,7,5,0,0,201,203,5,43,0,0,202,196,1,0,0,0,202,199,1,0,0,0,
203,208,1,0,0,0,204,205,10,3,0,0,205,207,3,28,14,4,206,204,1,0,0,0,207,210,
1,0,0,0,208,206,1,0,0,0,208,209,1,0,0,0,209,29,1,0,0,0,210,208,1,0,0,0,211,
212,5,42,0,0,212,225,5,41,0,0,213,214,5,42,0,0,214,219,3,32,16,0,215,216,
5,40,0,0,216,218,3,32,16,0,217,215,1,0,0,0,218,221,1,0,0,0,219,217,1,0,0,
0,219,220,1,0,0,0,220,222,1,0,0,0,221,219,1,0,0,0,222,223,5,41,0,0,223,225,
1,0,0,0,224,211,1,0,0,0,224,213,1,0,0,0,225,31,1,0,0,0,226,229,3,34,17,0,
227,229,5,8,0,0,228,226,1,0,0,0,228,227,1,0,0,0,229,33,1,0,0,0,230,231,7,
6,0,0,231,35,1,0,0,0,22,47,58,69,81,89,91,102,113,118,125,132,139,146,153,
160,171,190,202,208,219,224,228];


const atn = new antlr4.atn.ATNDeserializer().deserialize(serializedATN);

const decisionsToDFA = atn.decisionToState.map( (ds, index) => new antlr4.dfa.DFA(ds, index) );

const sharedContextCache = new antlr4.PredictionContextCache();

export default class STIXPatternParser extends antlr4.Parser {

    static grammarFileName = "STIXPattern.g4";
    static literalNames = [ null, null, null, null, null, null, null, null, 
                            null, null, "'AND'", "'OR'", "'NOT'", "'FOLLOWEDBY'", 
                            "'LIKE'", "'MATCHES'", "'ISSUPERSET'", "'ISSUBSET'", 
                            "'EXISTS'", "'LAST'", "'IN'", "'START'", "'STOP'", 
                            "'SECONDS'", "'true'", "'false'", "'WITHIN'", 
                            "'REPEATS'", "'TIMES'", null, null, null, null, 
                            "'<'", "'<='", "'>'", "'>='", "'''", "':'", 
                            "'.'", "','", "')'", "'('", "']'", "'['", "'+'", 
                            null, "'-'", "'^'", "'/'", "'*'" ];
    static symbolicNames = [ null, "IntNegLiteral", "IntPosLiteral", "FloatNegLiteral", 
                             "FloatPosLiteral", "HexLiteral", "BinaryLiteral", 
                             "StringLiteral", "BoolLiteral", "TimestampLiteral", 
                             "AND", "OR", "NOT", "FOLLOWEDBY", "LIKE", "MATCHES", 
                             "ISSUPERSET", "ISSUBSET", "EXISTS", "LAST", 
                             "IN", "START", "STOP", "SECONDS", "TRUE", "FALSE", 
                             "WITHIN", "REPEATS", "TIMES", "IdentifierWithoutHyphen", 
                             "IdentifierWithHyphen", "EQ", "NEQ", "LT", 
                             "LE", "GT", "GE", "QUOTE", "COLON", "DOT", 
                             "COMMA", "RPAREN", "LPAREN", "RBRACK", "LBRACK", 
                             "PLUS", "HYPHEN", "MINUS", "POWER_OP", "DIVIDE", 
                             "ASTERISK", "WS", "COMMENT", "LINE_COMMENT", 
                             "InvalidCharacter" ];
    static ruleNames = [ "pattern", "observationExpressions", "observationExpressionOr", 
                         "observationExpressionAnd", "observationExpression", 
                         "comparisonExpression", "comparisonExpressionAnd", 
                         "propTest", "startStopQualifier", "withinQualifier", 
                         "repeatedQualifier", "objectPath", "objectType", 
                         "firstPathComponent", "objectPathComponent", "setLiteral", 
                         "primitiveLiteral", "orderableLiteral" ];

    constructor(input) {
        super(input);
        this._interp = new antlr4.atn.ParserATNSimulator(this, atn, decisionsToDFA, sharedContextCache);
        this.ruleNames = STIXPatternParser.ruleNames;
        this.literalNames = STIXPatternParser.literalNames;
        this.symbolicNames = STIXPatternParser.symbolicNames;
    }

    get atn() {
        return atn;
    }

    sempred(localctx, ruleIndex, predIndex) {
    	switch(ruleIndex) {
    	case 1:
    	    		return this.observationExpressions_sempred(localctx, predIndex);
    	case 2:
    	    		return this.observationExpressionOr_sempred(localctx, predIndex);
    	case 3:
    	    		return this.observationExpressionAnd_sempred(localctx, predIndex);
    	case 4:
    	    		return this.observationExpression_sempred(localctx, predIndex);
    	case 5:
    	    		return this.comparisonExpression_sempred(localctx, predIndex);
    	case 6:
    	    		return this.comparisonExpressionAnd_sempred(localctx, predIndex);
    	case 14:
    	    		return this.objectPathComponent_sempred(localctx, predIndex);
        default:
            throw "No predicate with index:" + ruleIndex;
       }
    }

    observationExpressions_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 0:
    			return this.precpred(this._ctx, 2);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    observationExpressionOr_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 1:
    			return this.precpred(this._ctx, 2);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    observationExpressionAnd_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 2:
    			return this.precpred(this._ctx, 2);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    observationExpression_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 3:
    			return this.precpred(this._ctx, 3);
    		case 4:
    			return this.precpred(this._ctx, 2);
    		case 5:
    			return this.precpred(this._ctx, 1);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    comparisonExpression_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 6:
    			return this.precpred(this._ctx, 2);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    comparisonExpressionAnd_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 7:
    			return this.precpred(this._ctx, 2);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };

    objectPathComponent_sempred(localctx, predIndex) {
    	switch(predIndex) {
    		case 8:
    			return this.precpred(this._ctx, 3);
    		default:
    			throw "No predicate with index:" + predIndex;
    	}
    };




	pattern() {
	    let localctx = new PatternContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 0, STIXPatternParser.RULE_pattern);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 36;
	        this.observationExpressions(0);
	        this.state = 37;
	        this.match(STIXPatternParser.EOF);
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}


	observationExpressions(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ObservationExpressionsContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 2;
	    this.enterRecursionRule(localctx, 2, STIXPatternParser.RULE_observationExpressions, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 40;
	        this.observationExpressionOr(0);
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 47;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,0,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new ObservationExpressionsContext(this, _parentctx, _parentState);
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpressions);
	                this.state = 42;
	                if (!( this.precpred(this._ctx, 2))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                }
	                this.state = 43;
	                this.match(STIXPatternParser.FOLLOWEDBY);
	                this.state = 44;
	                this.observationExpressions(3); 
	            }
	            this.state = 49;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,0,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}


	observationExpressionOr(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ObservationExpressionOrContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 4;
	    this.enterRecursionRule(localctx, 4, STIXPatternParser.RULE_observationExpressionOr, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 51;
	        this.observationExpressionAnd(0);
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 58;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,1,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new ObservationExpressionOrContext(this, _parentctx, _parentState);
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpressionOr);
	                this.state = 53;
	                if (!( this.precpred(this._ctx, 2))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                }
	                this.state = 54;
	                this.match(STIXPatternParser.OR);
	                this.state = 55;
	                this.observationExpressionOr(3); 
	            }
	            this.state = 60;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,1,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}


	observationExpressionAnd(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ObservationExpressionAndContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 6;
	    this.enterRecursionRule(localctx, 6, STIXPatternParser.RULE_observationExpressionAnd, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 62;
	        this.observationExpression(0);
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 69;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,2,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new ObservationExpressionAndContext(this, _parentctx, _parentState);
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpressionAnd);
	                this.state = 64;
	                if (!( this.precpred(this._ctx, 2))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                }
	                this.state = 65;
	                this.match(STIXPatternParser.AND);
	                this.state = 66;
	                this.observationExpressionAnd(3); 
	            }
	            this.state = 71;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,2,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}


	observationExpression(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ObservationExpressionContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 8;
	    this.enterRecursionRule(localctx, 8, STIXPatternParser.RULE_observationExpression, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 81;
	        this._errHandler.sync(this);
	        switch(this._input.LA(1)) {
	        case STIXPatternParser.LBRACK:
	            localctx = new ObservationExpressionSimpleContext(this, localctx);
	            this._ctx = localctx;
	            _prevctx = localctx;

	            this.state = 73;
	            this.match(STIXPatternParser.LBRACK);
	            this.state = 74;
	            this.comparisonExpression(0);
	            this.state = 75;
	            this.match(STIXPatternParser.RBRACK);
	            break;
	        case STIXPatternParser.LPAREN:
	            localctx = new ObservationExpressionCompoundContext(this, localctx);
	            this._ctx = localctx;
	            _prevctx = localctx;
	            this.state = 77;
	            this.match(STIXPatternParser.LPAREN);
	            this.state = 78;
	            this.observationExpressions(0);
	            this.state = 79;
	            this.match(STIXPatternParser.RPAREN);
	            break;
	        default:
	            throw new antlr4.error.NoViableAltException(this);
	        }
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 91;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,5,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                this.state = 89;
	                this._errHandler.sync(this);
	                var la_ = this._interp.adaptivePredict(this._input,4,this._ctx);
	                switch(la_) {
	                case 1:
	                    localctx = new ObservationExpressionStartStopContext(this, new ObservationExpressionContext(this, _parentctx, _parentState));
	                    this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpression);
	                    this.state = 83;
	                    if (!( this.precpred(this._ctx, 3))) {
	                        throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 3)");
	                    }
	                    this.state = 84;
	                    this.startStopQualifier();
	                    break;

	                case 2:
	                    localctx = new ObservationExpressionWithinContext(this, new ObservationExpressionContext(this, _parentctx, _parentState));
	                    this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpression);
	                    this.state = 85;
	                    if (!( this.precpred(this._ctx, 2))) {
	                        throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                    }
	                    this.state = 86;
	                    this.withinQualifier();
	                    break;

	                case 3:
	                    localctx = new ObservationExpressionRepeatedContext(this, new ObservationExpressionContext(this, _parentctx, _parentState));
	                    this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_observationExpression);
	                    this.state = 87;
	                    if (!( this.precpred(this._ctx, 1))) {
	                        throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 1)");
	                    }
	                    this.state = 88;
	                    this.repeatedQualifier();
	                    break;

	                } 
	            }
	            this.state = 93;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,5,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}


	comparisonExpression(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ComparisonExpressionContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 10;
	    this.enterRecursionRule(localctx, 10, STIXPatternParser.RULE_comparisonExpression, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 95;
	        this.comparisonExpressionAnd(0);
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 102;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,6,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new ComparisonExpressionContext(this, _parentctx, _parentState);
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_comparisonExpression);
	                this.state = 97;
	                if (!( this.precpred(this._ctx, 2))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                }
	                this.state = 98;
	                this.match(STIXPatternParser.OR);
	                this.state = 99;
	                this.comparisonExpression(3); 
	            }
	            this.state = 104;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,6,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}


	comparisonExpressionAnd(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ComparisonExpressionAndContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 12;
	    this.enterRecursionRule(localctx, 12, STIXPatternParser.RULE_comparisonExpressionAnd, _p);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 106;
	        this.propTest();
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 113;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,7,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new ComparisonExpressionAndContext(this, _parentctx, _parentState);
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_comparisonExpressionAnd);
	                this.state = 108;
	                if (!( this.precpred(this._ctx, 2))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 2)");
	                }
	                this.state = 109;
	                this.match(STIXPatternParser.AND);
	                this.state = 110;
	                this.comparisonExpressionAnd(3); 
	            }
	            this.state = 115;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,7,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}



	propTest() {
	    let localctx = new PropTestContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 14, STIXPatternParser.RULE_propTest);
	    var _la = 0; // Token type
	    try {
	        this.state = 171;
	        this._errHandler.sync(this);
	        var la_ = this._interp.adaptivePredict(this._input,15,this._ctx);
	        switch(la_) {
	        case 1:
	            localctx = new PropTestEqualContext(this, localctx);
	            this.enterOuterAlt(localctx, 1);
	            this.state = 116;
	            this.objectPath();
	            this.state = 118;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 117;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 120;
	            _la = this._input.LA(1);
	            if(!(_la===STIXPatternParser.EQ || _la===STIXPatternParser.NEQ)) {
	            this._errHandler.recoverInline(this);
	            }
	            else {
	            	this._errHandler.reportMatch(this);
	                this.consume();
	            }
	            this.state = 121;
	            this.primitiveLiteral();
	            break;

	        case 2:
	            localctx = new PropTestOrderContext(this, localctx);
	            this.enterOuterAlt(localctx, 2);
	            this.state = 123;
	            this.objectPath();
	            this.state = 125;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 124;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 127;
	            _la = this._input.LA(1);
	            if(!(((((_la - 33)) & ~0x1f) == 0 && ((1 << (_la - 33)) & ((1 << (STIXPatternParser.LT - 33)) | (1 << (STIXPatternParser.LE - 33)) | (1 << (STIXPatternParser.GT - 33)) | (1 << (STIXPatternParser.GE - 33)))) !== 0))) {
	            this._errHandler.recoverInline(this);
	            }
	            else {
	            	this._errHandler.reportMatch(this);
	                this.consume();
	            }
	            this.state = 128;
	            this.orderableLiteral();
	            break;

	        case 3:
	            localctx = new PropTestSetContext(this, localctx);
	            this.enterOuterAlt(localctx, 3);
	            this.state = 130;
	            this.objectPath();
	            this.state = 132;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 131;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 134;
	            this.match(STIXPatternParser.IN);
	            this.state = 135;
	            this.setLiteral();
	            break;

	        case 4:
	            localctx = new PropTestLikeContext(this, localctx);
	            this.enterOuterAlt(localctx, 4);
	            this.state = 137;
	            this.objectPath();
	            this.state = 139;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 138;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 141;
	            this.match(STIXPatternParser.LIKE);
	            this.state = 142;
	            this.match(STIXPatternParser.StringLiteral);
	            break;

	        case 5:
	            localctx = new PropTestRegexContext(this, localctx);
	            this.enterOuterAlt(localctx, 5);
	            this.state = 144;
	            this.objectPath();
	            this.state = 146;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 145;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 148;
	            this.match(STIXPatternParser.MATCHES);
	            this.state = 149;
	            this.match(STIXPatternParser.StringLiteral);
	            break;

	        case 6:
	            localctx = new PropTestIsSubsetContext(this, localctx);
	            this.enterOuterAlt(localctx, 6);
	            this.state = 151;
	            this.objectPath();
	            this.state = 153;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 152;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 155;
	            this.match(STIXPatternParser.ISSUBSET);
	            this.state = 156;
	            this.match(STIXPatternParser.StringLiteral);
	            break;

	        case 7:
	            localctx = new PropTestIsSupersetContext(this, localctx);
	            this.enterOuterAlt(localctx, 7);
	            this.state = 158;
	            this.objectPath();
	            this.state = 160;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            if(_la===STIXPatternParser.NOT) {
	                this.state = 159;
	                this.match(STIXPatternParser.NOT);
	            }

	            this.state = 162;
	            this.match(STIXPatternParser.ISSUPERSET);
	            this.state = 163;
	            this.match(STIXPatternParser.StringLiteral);
	            break;

	        case 8:
	            localctx = new PropTestParenContext(this, localctx);
	            this.enterOuterAlt(localctx, 8);
	            this.state = 165;
	            this.match(STIXPatternParser.LPAREN);
	            this.state = 166;
	            this.comparisonExpression(0);
	            this.state = 167;
	            this.match(STIXPatternParser.RPAREN);
	            break;

	        case 9:
	            localctx = new PropTestExistsContext(this, localctx);
	            this.enterOuterAlt(localctx, 9);
	            this.state = 169;
	            this.match(STIXPatternParser.EXISTS);
	            this.state = 170;
	            this.objectPath();
	            break;

	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	startStopQualifier() {
	    let localctx = new StartStopQualifierContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 16, STIXPatternParser.RULE_startStopQualifier);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 173;
	        this.match(STIXPatternParser.START);
	        this.state = 174;
	        this.match(STIXPatternParser.TimestampLiteral);
	        this.state = 175;
	        this.match(STIXPatternParser.STOP);
	        this.state = 176;
	        this.match(STIXPatternParser.TimestampLiteral);
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	withinQualifier() {
	    let localctx = new WithinQualifierContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 18, STIXPatternParser.RULE_withinQualifier);
	    var _la = 0; // Token type
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 178;
	        this.match(STIXPatternParser.WITHIN);
	        this.state = 179;
	        _la = this._input.LA(1);
	        if(!(_la===STIXPatternParser.IntPosLiteral || _la===STIXPatternParser.FloatPosLiteral)) {
	        this._errHandler.recoverInline(this);
	        }
	        else {
	        	this._errHandler.reportMatch(this);
	            this.consume();
	        }
	        this.state = 180;
	        this.match(STIXPatternParser.SECONDS);
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	repeatedQualifier() {
	    let localctx = new RepeatedQualifierContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 20, STIXPatternParser.RULE_repeatedQualifier);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 182;
	        this.match(STIXPatternParser.REPEATS);
	        this.state = 183;
	        this.match(STIXPatternParser.IntPosLiteral);
	        this.state = 184;
	        this.match(STIXPatternParser.TIMES);
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	objectPath() {
	    let localctx = new ObjectPathContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 22, STIXPatternParser.RULE_objectPath);
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 186;
	        this.objectType();
	        this.state = 187;
	        this.match(STIXPatternParser.COLON);
	        this.state = 188;
	        this.firstPathComponent();
	        this.state = 190;
	        this._errHandler.sync(this);
	        var la_ = this._interp.adaptivePredict(this._input,16,this._ctx);
	        if(la_===1) {
	            this.state = 189;
	            this.objectPathComponent(0);

	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	objectType() {
	    let localctx = new ObjectTypeContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 24, STIXPatternParser.RULE_objectType);
	    var _la = 0; // Token type
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 192;
	        _la = this._input.LA(1);
	        if(!(_la===STIXPatternParser.IdentifierWithoutHyphen || _la===STIXPatternParser.IdentifierWithHyphen)) {
	        this._errHandler.recoverInline(this);
	        }
	        else {
	        	this._errHandler.reportMatch(this);
	            this.consume();
	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	firstPathComponent() {
	    let localctx = new FirstPathComponentContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 26, STIXPatternParser.RULE_firstPathComponent);
	    var _la = 0; // Token type
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 194;
	        _la = this._input.LA(1);
	        if(!(_la===STIXPatternParser.StringLiteral || _la===STIXPatternParser.IdentifierWithoutHyphen)) {
	        this._errHandler.recoverInline(this);
	        }
	        else {
	        	this._errHandler.reportMatch(this);
	            this.consume();
	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}


	objectPathComponent(_p) {
		if(_p===undefined) {
		    _p = 0;
		}
	    const _parentctx = this._ctx;
	    const _parentState = this.state;
	    let localctx = new ObjectPathComponentContext(this, this._ctx, _parentState);
	    let _prevctx = localctx;
	    const _startState = 28;
	    this.enterRecursionRule(localctx, 28, STIXPatternParser.RULE_objectPathComponent, _p);
	    var _la = 0; // Token type
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 202;
	        this._errHandler.sync(this);
	        switch(this._input.LA(1)) {
	        case STIXPatternParser.DOT:
	            localctx = new KeyPathStepContext(this, localctx);
	            this._ctx = localctx;
	            _prevctx = localctx;

	            this.state = 197;
	            this.match(STIXPatternParser.DOT);
	            this.state = 198;
	            _la = this._input.LA(1);
	            if(!(_la===STIXPatternParser.StringLiteral || _la===STIXPatternParser.IdentifierWithoutHyphen)) {
	            this._errHandler.recoverInline(this);
	            }
	            else {
	            	this._errHandler.reportMatch(this);
	                this.consume();
	            }
	            break;
	        case STIXPatternParser.LBRACK:
	            localctx = new IndexPathStepContext(this, localctx);
	            this._ctx = localctx;
	            _prevctx = localctx;
	            this.state = 199;
	            this.match(STIXPatternParser.LBRACK);
	            this.state = 200;
	            _la = this._input.LA(1);
	            if(!(_la===STIXPatternParser.IntNegLiteral || _la===STIXPatternParser.IntPosLiteral || _la===STIXPatternParser.ASTERISK)) {
	            this._errHandler.recoverInline(this);
	            }
	            else {
	            	this._errHandler.reportMatch(this);
	                this.consume();
	            }
	            this.state = 201;
	            this.match(STIXPatternParser.RBRACK);
	            break;
	        default:
	            throw new antlr4.error.NoViableAltException(this);
	        }
	        this._ctx.stop = this._input.LT(-1);
	        this.state = 208;
	        this._errHandler.sync(this);
	        var _alt = this._interp.adaptivePredict(this._input,18,this._ctx)
	        while(_alt!=2 && _alt!=antlr4.atn.ATN.INVALID_ALT_NUMBER) {
	            if(_alt===1) {
	                if(this._parseListeners!==null) {
	                    this.triggerExitRuleEvent();
	                }
	                _prevctx = localctx;
	                localctx = new PathStepContext(this, new ObjectPathComponentContext(this, _parentctx, _parentState));
	                this.pushNewRecursionContext(localctx, _startState, STIXPatternParser.RULE_objectPathComponent);
	                this.state = 204;
	                if (!( this.precpred(this._ctx, 3))) {
	                    throw new antlr4.error.FailedPredicateException(this, "this.precpred(this._ctx, 3)");
	                }
	                this.state = 205;
	                this.objectPathComponent(4); 
	            }
	            this.state = 210;
	            this._errHandler.sync(this);
	            _alt = this._interp.adaptivePredict(this._input,18,this._ctx);
	        }

	    } catch( error) {
	        if(error instanceof antlr4.error.RecognitionException) {
		        localctx.exception = error;
		        this._errHandler.reportError(this, error);
		        this._errHandler.recover(this, error);
		    } else {
		    	throw error;
		    }
	    } finally {
	        this.unrollRecursionContexts(_parentctx)
	    }
	    return localctx;
	}



	setLiteral() {
	    let localctx = new SetLiteralContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 30, STIXPatternParser.RULE_setLiteral);
	    var _la = 0; // Token type
	    try {
	        this.state = 224;
	        this._errHandler.sync(this);
	        var la_ = this._interp.adaptivePredict(this._input,20,this._ctx);
	        switch(la_) {
	        case 1:
	            this.enterOuterAlt(localctx, 1);
	            this.state = 211;
	            this.match(STIXPatternParser.LPAREN);
	            this.state = 212;
	            this.match(STIXPatternParser.RPAREN);
	            break;

	        case 2:
	            this.enterOuterAlt(localctx, 2);
	            this.state = 213;
	            this.match(STIXPatternParser.LPAREN);
	            this.state = 214;
	            this.primitiveLiteral();
	            this.state = 219;
	            this._errHandler.sync(this);
	            _la = this._input.LA(1);
	            while(_la===STIXPatternParser.COMMA) {
	                this.state = 215;
	                this.match(STIXPatternParser.COMMA);
	                this.state = 216;
	                this.primitiveLiteral();
	                this.state = 221;
	                this._errHandler.sync(this);
	                _la = this._input.LA(1);
	            }
	            this.state = 222;
	            this.match(STIXPatternParser.RPAREN);
	            break;

	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	primitiveLiteral() {
	    let localctx = new PrimitiveLiteralContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 32, STIXPatternParser.RULE_primitiveLiteral);
	    try {
	        this.state = 228;
	        this._errHandler.sync(this);
	        switch(this._input.LA(1)) {
	        case STIXPatternParser.IntNegLiteral:
	        case STIXPatternParser.IntPosLiteral:
	        case STIXPatternParser.FloatNegLiteral:
	        case STIXPatternParser.FloatPosLiteral:
	        case STIXPatternParser.HexLiteral:
	        case STIXPatternParser.BinaryLiteral:
	        case STIXPatternParser.StringLiteral:
	        case STIXPatternParser.TimestampLiteral:
	            this.enterOuterAlt(localctx, 1);
	            this.state = 226;
	            this.orderableLiteral();
	            break;
	        case STIXPatternParser.BoolLiteral:
	            this.enterOuterAlt(localctx, 2);
	            this.state = 227;
	            this.match(STIXPatternParser.BoolLiteral);
	            break;
	        default:
	            throw new antlr4.error.NoViableAltException(this);
	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}



	orderableLiteral() {
	    let localctx = new OrderableLiteralContext(this, this._ctx, this.state);
	    this.enterRule(localctx, 34, STIXPatternParser.RULE_orderableLiteral);
	    var _la = 0; // Token type
	    try {
	        this.enterOuterAlt(localctx, 1);
	        this.state = 230;
	        _la = this._input.LA(1);
	        if(!((((_la) & ~0x1f) == 0 && ((1 << _la) & ((1 << STIXPatternParser.IntNegLiteral) | (1 << STIXPatternParser.IntPosLiteral) | (1 << STIXPatternParser.FloatNegLiteral) | (1 << STIXPatternParser.FloatPosLiteral) | (1 << STIXPatternParser.HexLiteral) | (1 << STIXPatternParser.BinaryLiteral) | (1 << STIXPatternParser.StringLiteral) | (1 << STIXPatternParser.TimestampLiteral))) !== 0))) {
	        this._errHandler.recoverInline(this);
	        }
	        else {
	        	this._errHandler.reportMatch(this);
	            this.consume();
	        }
	    } catch (re) {
	    	if(re instanceof antlr4.error.RecognitionException) {
		        localctx.exception = re;
		        this._errHandler.reportError(this, re);
		        this._errHandler.recover(this, re);
		    } else {
		    	throw re;
		    }
	    } finally {
	        this.exitRule();
	    }
	    return localctx;
	}


}

STIXPatternParser.EOF = antlr4.Token.EOF;
STIXPatternParser.IntNegLiteral = 1;
STIXPatternParser.IntPosLiteral = 2;
STIXPatternParser.FloatNegLiteral = 3;
STIXPatternParser.FloatPosLiteral = 4;
STIXPatternParser.HexLiteral = 5;
STIXPatternParser.BinaryLiteral = 6;
STIXPatternParser.StringLiteral = 7;
STIXPatternParser.BoolLiteral = 8;
STIXPatternParser.TimestampLiteral = 9;
STIXPatternParser.AND = 10;
STIXPatternParser.OR = 11;
STIXPatternParser.NOT = 12;
STIXPatternParser.FOLLOWEDBY = 13;
STIXPatternParser.LIKE = 14;
STIXPatternParser.MATCHES = 15;
STIXPatternParser.ISSUPERSET = 16;
STIXPatternParser.ISSUBSET = 17;
STIXPatternParser.EXISTS = 18;
STIXPatternParser.LAST = 19;
STIXPatternParser.IN = 20;
STIXPatternParser.START = 21;
STIXPatternParser.STOP = 22;
STIXPatternParser.SECONDS = 23;
STIXPatternParser.TRUE = 24;
STIXPatternParser.FALSE = 25;
STIXPatternParser.WITHIN = 26;
STIXPatternParser.REPEATS = 27;
STIXPatternParser.TIMES = 28;
STIXPatternParser.IdentifierWithoutHyphen = 29;
STIXPatternParser.IdentifierWithHyphen = 30;
STIXPatternParser.EQ = 31;
STIXPatternParser.NEQ = 32;
STIXPatternParser.LT = 33;
STIXPatternParser.LE = 34;
STIXPatternParser.GT = 35;
STIXPatternParser.GE = 36;
STIXPatternParser.QUOTE = 37;
STIXPatternParser.COLON = 38;
STIXPatternParser.DOT = 39;
STIXPatternParser.COMMA = 40;
STIXPatternParser.RPAREN = 41;
STIXPatternParser.LPAREN = 42;
STIXPatternParser.RBRACK = 43;
STIXPatternParser.LBRACK = 44;
STIXPatternParser.PLUS = 45;
STIXPatternParser.HYPHEN = 46;
STIXPatternParser.MINUS = 47;
STIXPatternParser.POWER_OP = 48;
STIXPatternParser.DIVIDE = 49;
STIXPatternParser.ASTERISK = 50;
STIXPatternParser.WS = 51;
STIXPatternParser.COMMENT = 52;
STIXPatternParser.LINE_COMMENT = 53;
STIXPatternParser.InvalidCharacter = 54;

STIXPatternParser.RULE_pattern = 0;
STIXPatternParser.RULE_observationExpressions = 1;
STIXPatternParser.RULE_observationExpressionOr = 2;
STIXPatternParser.RULE_observationExpressionAnd = 3;
STIXPatternParser.RULE_observationExpression = 4;
STIXPatternParser.RULE_comparisonExpression = 5;
STIXPatternParser.RULE_comparisonExpressionAnd = 6;
STIXPatternParser.RULE_propTest = 7;
STIXPatternParser.RULE_startStopQualifier = 8;
STIXPatternParser.RULE_withinQualifier = 9;
STIXPatternParser.RULE_repeatedQualifier = 10;
STIXPatternParser.RULE_objectPath = 11;
STIXPatternParser.RULE_objectType = 12;
STIXPatternParser.RULE_firstPathComponent = 13;
STIXPatternParser.RULE_objectPathComponent = 14;
STIXPatternParser.RULE_setLiteral = 15;
STIXPatternParser.RULE_primitiveLiteral = 16;
STIXPatternParser.RULE_orderableLiteral = 17;

class PatternContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_pattern;
    }

	observationExpressions() {
	    return this.getTypedRuleContext(ObservationExpressionsContext,0);
	};

	EOF() {
	    return this.getToken(STIXPatternParser.EOF, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPattern(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPattern(this);
		}
	}


}



class ObservationExpressionsContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_observationExpressions;
    }

	observationExpressionOr() {
	    return this.getTypedRuleContext(ObservationExpressionOrContext,0);
	};

	observationExpressions = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ObservationExpressionsContext);
	    } else {
	        return this.getTypedRuleContext(ObservationExpressionsContext,i);
	    }
	};

	FOLLOWEDBY() {
	    return this.getToken(STIXPatternParser.FOLLOWEDBY, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressions(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressions(this);
		}
	}


}



class ObservationExpressionOrContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_observationExpressionOr;
    }

	observationExpressionAnd() {
	    return this.getTypedRuleContext(ObservationExpressionAndContext,0);
	};

	observationExpressionOr = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ObservationExpressionOrContext);
	    } else {
	        return this.getTypedRuleContext(ObservationExpressionOrContext,i);
	    }
	};

	OR() {
	    return this.getToken(STIXPatternParser.OR, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionOr(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionOr(this);
		}
	}


}



class ObservationExpressionAndContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_observationExpressionAnd;
    }

	observationExpression() {
	    return this.getTypedRuleContext(ObservationExpressionContext,0);
	};

	observationExpressionAnd = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ObservationExpressionAndContext);
	    } else {
	        return this.getTypedRuleContext(ObservationExpressionAndContext,i);
	    }
	};

	AND() {
	    return this.getToken(STIXPatternParser.AND, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionAnd(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionAnd(this);
		}
	}


}



class ObservationExpressionContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_observationExpression;
    }


	 
		copyFrom(ctx) {
			super.copyFrom(ctx);
		}

}


class ObservationExpressionRepeatedContext extends ObservationExpressionContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	observationExpression() {
	    return this.getTypedRuleContext(ObservationExpressionContext,0);
	};

	repeatedQualifier() {
	    return this.getTypedRuleContext(RepeatedQualifierContext,0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionRepeated(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionRepeated(this);
		}
	}


}

STIXPatternParser.ObservationExpressionRepeatedContext = ObservationExpressionRepeatedContext;

class ObservationExpressionSimpleContext extends ObservationExpressionContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	LBRACK() {
	    return this.getToken(STIXPatternParser.LBRACK, 0);
	};

	comparisonExpression() {
	    return this.getTypedRuleContext(ComparisonExpressionContext,0);
	};

	RBRACK() {
	    return this.getToken(STIXPatternParser.RBRACK, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionSimple(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionSimple(this);
		}
	}


}

STIXPatternParser.ObservationExpressionSimpleContext = ObservationExpressionSimpleContext;

class ObservationExpressionCompoundContext extends ObservationExpressionContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	LPAREN() {
	    return this.getToken(STIXPatternParser.LPAREN, 0);
	};

	observationExpressions() {
	    return this.getTypedRuleContext(ObservationExpressionsContext,0);
	};

	RPAREN() {
	    return this.getToken(STIXPatternParser.RPAREN, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionCompound(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionCompound(this);
		}
	}


}

STIXPatternParser.ObservationExpressionCompoundContext = ObservationExpressionCompoundContext;

class ObservationExpressionWithinContext extends ObservationExpressionContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	observationExpression() {
	    return this.getTypedRuleContext(ObservationExpressionContext,0);
	};

	withinQualifier() {
	    return this.getTypedRuleContext(WithinQualifierContext,0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionWithin(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionWithin(this);
		}
	}


}

STIXPatternParser.ObservationExpressionWithinContext = ObservationExpressionWithinContext;

class ObservationExpressionStartStopContext extends ObservationExpressionContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	observationExpression() {
	    return this.getTypedRuleContext(ObservationExpressionContext,0);
	};

	startStopQualifier() {
	    return this.getTypedRuleContext(StartStopQualifierContext,0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObservationExpressionStartStop(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObservationExpressionStartStop(this);
		}
	}


}

STIXPatternParser.ObservationExpressionStartStopContext = ObservationExpressionStartStopContext;

class ComparisonExpressionContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_comparisonExpression;
    }

	comparisonExpressionAnd() {
	    return this.getTypedRuleContext(ComparisonExpressionAndContext,0);
	};

	comparisonExpression = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ComparisonExpressionContext);
	    } else {
	        return this.getTypedRuleContext(ComparisonExpressionContext,i);
	    }
	};

	OR() {
	    return this.getToken(STIXPatternParser.OR, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterComparisonExpression(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitComparisonExpression(this);
		}
	}


}



class ComparisonExpressionAndContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_comparisonExpressionAnd;
    }

	propTest() {
	    return this.getTypedRuleContext(PropTestContext,0);
	};

	comparisonExpressionAnd = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ComparisonExpressionAndContext);
	    } else {
	        return this.getTypedRuleContext(ComparisonExpressionAndContext,i);
	    }
	};

	AND() {
	    return this.getToken(STIXPatternParser.AND, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterComparisonExpressionAnd(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitComparisonExpressionAnd(this);
		}
	}


}



class PropTestContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_propTest;
    }


	 
		copyFrom(ctx) {
			super.copyFrom(ctx);
		}

}


class PropTestExistsContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	EXISTS() {
	    return this.getToken(STIXPatternParser.EXISTS, 0);
	};

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestExists(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestExists(this);
		}
	}


}

STIXPatternParser.PropTestExistsContext = PropTestExistsContext;

class PropTestRegexContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	MATCHES() {
	    return this.getToken(STIXPatternParser.MATCHES, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestRegex(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestRegex(this);
		}
	}


}

STIXPatternParser.PropTestRegexContext = PropTestRegexContext;

class PropTestOrderContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	orderableLiteral() {
	    return this.getTypedRuleContext(OrderableLiteralContext,0);
	};

	GT() {
	    return this.getToken(STIXPatternParser.GT, 0);
	};

	LT() {
	    return this.getToken(STIXPatternParser.LT, 0);
	};

	GE() {
	    return this.getToken(STIXPatternParser.GE, 0);
	};

	LE() {
	    return this.getToken(STIXPatternParser.LE, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestOrder(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestOrder(this);
		}
	}


}

STIXPatternParser.PropTestOrderContext = PropTestOrderContext;

class PropTestLikeContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	LIKE() {
	    return this.getToken(STIXPatternParser.LIKE, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestLike(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestLike(this);
		}
	}


}

STIXPatternParser.PropTestLikeContext = PropTestLikeContext;

class PropTestEqualContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	primitiveLiteral() {
	    return this.getTypedRuleContext(PrimitiveLiteralContext,0);
	};

	EQ() {
	    return this.getToken(STIXPatternParser.EQ, 0);
	};

	NEQ() {
	    return this.getToken(STIXPatternParser.NEQ, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestEqual(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestEqual(this);
		}
	}


}

STIXPatternParser.PropTestEqualContext = PropTestEqualContext;

class PropTestSetContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	IN() {
	    return this.getToken(STIXPatternParser.IN, 0);
	};

	setLiteral() {
	    return this.getTypedRuleContext(SetLiteralContext,0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestSet(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestSet(this);
		}
	}


}

STIXPatternParser.PropTestSetContext = PropTestSetContext;

class PropTestIsSubsetContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	ISSUBSET() {
	    return this.getToken(STIXPatternParser.ISSUBSET, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestIsSubset(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestIsSubset(this);
		}
	}


}

STIXPatternParser.PropTestIsSubsetContext = PropTestIsSubsetContext;

class PropTestParenContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	LPAREN() {
	    return this.getToken(STIXPatternParser.LPAREN, 0);
	};

	comparisonExpression() {
	    return this.getTypedRuleContext(ComparisonExpressionContext,0);
	};

	RPAREN() {
	    return this.getToken(STIXPatternParser.RPAREN, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestParen(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestParen(this);
		}
	}


}

STIXPatternParser.PropTestParenContext = PropTestParenContext;

class PropTestIsSupersetContext extends PropTestContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPath() {
	    return this.getTypedRuleContext(ObjectPathContext,0);
	};

	ISSUPERSET() {
	    return this.getToken(STIXPatternParser.ISSUPERSET, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	NOT() {
	    return this.getToken(STIXPatternParser.NOT, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPropTestIsSuperset(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPropTestIsSuperset(this);
		}
	}


}

STIXPatternParser.PropTestIsSupersetContext = PropTestIsSupersetContext;

class StartStopQualifierContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_startStopQualifier;
    }

	START() {
	    return this.getToken(STIXPatternParser.START, 0);
	};

	TimestampLiteral = function(i) {
		if(i===undefined) {
			i = null;
		}
	    if(i===null) {
	        return this.getTokens(STIXPatternParser.TimestampLiteral);
	    } else {
	        return this.getToken(STIXPatternParser.TimestampLiteral, i);
	    }
	};


	STOP() {
	    return this.getToken(STIXPatternParser.STOP, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterStartStopQualifier(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitStartStopQualifier(this);
		}
	}


}



class WithinQualifierContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_withinQualifier;
    }

	WITHIN() {
	    return this.getToken(STIXPatternParser.WITHIN, 0);
	};

	SECONDS() {
	    return this.getToken(STIXPatternParser.SECONDS, 0);
	};

	IntPosLiteral() {
	    return this.getToken(STIXPatternParser.IntPosLiteral, 0);
	};

	FloatPosLiteral() {
	    return this.getToken(STIXPatternParser.FloatPosLiteral, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterWithinQualifier(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitWithinQualifier(this);
		}
	}


}



class RepeatedQualifierContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_repeatedQualifier;
    }

	REPEATS() {
	    return this.getToken(STIXPatternParser.REPEATS, 0);
	};

	IntPosLiteral() {
	    return this.getToken(STIXPatternParser.IntPosLiteral, 0);
	};

	TIMES() {
	    return this.getToken(STIXPatternParser.TIMES, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterRepeatedQualifier(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitRepeatedQualifier(this);
		}
	}


}



class ObjectPathContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_objectPath;
    }

	objectType() {
	    return this.getTypedRuleContext(ObjectTypeContext,0);
	};

	COLON() {
	    return this.getToken(STIXPatternParser.COLON, 0);
	};

	firstPathComponent() {
	    return this.getTypedRuleContext(FirstPathComponentContext,0);
	};

	objectPathComponent() {
	    return this.getTypedRuleContext(ObjectPathComponentContext,0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObjectPath(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObjectPath(this);
		}
	}


}



class ObjectTypeContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_objectType;
    }

	IdentifierWithoutHyphen() {
	    return this.getToken(STIXPatternParser.IdentifierWithoutHyphen, 0);
	};

	IdentifierWithHyphen() {
	    return this.getToken(STIXPatternParser.IdentifierWithHyphen, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterObjectType(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitObjectType(this);
		}
	}


}



class FirstPathComponentContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_firstPathComponent;
    }

	IdentifierWithoutHyphen() {
	    return this.getToken(STIXPatternParser.IdentifierWithoutHyphen, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterFirstPathComponent(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitFirstPathComponent(this);
		}
	}


}



class ObjectPathComponentContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_objectPathComponent;
    }


	 
		copyFrom(ctx) {
			super.copyFrom(ctx);
		}

}


class IndexPathStepContext extends ObjectPathComponentContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	LBRACK() {
	    return this.getToken(STIXPatternParser.LBRACK, 0);
	};

	RBRACK() {
	    return this.getToken(STIXPatternParser.RBRACK, 0);
	};

	IntPosLiteral() {
	    return this.getToken(STIXPatternParser.IntPosLiteral, 0);
	};

	IntNegLiteral() {
	    return this.getToken(STIXPatternParser.IntNegLiteral, 0);
	};

	ASTERISK() {
	    return this.getToken(STIXPatternParser.ASTERISK, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterIndexPathStep(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitIndexPathStep(this);
		}
	}


}

STIXPatternParser.IndexPathStepContext = IndexPathStepContext;

class PathStepContext extends ObjectPathComponentContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	objectPathComponent = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(ObjectPathComponentContext);
	    } else {
	        return this.getTypedRuleContext(ObjectPathComponentContext,i);
	    }
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPathStep(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPathStep(this);
		}
	}


}

STIXPatternParser.PathStepContext = PathStepContext;

class KeyPathStepContext extends ObjectPathComponentContext {

    constructor(parser, ctx) {
        super(parser);
        super.copyFrom(ctx);
    }

	DOT() {
	    return this.getToken(STIXPatternParser.DOT, 0);
	};

	IdentifierWithoutHyphen() {
	    return this.getToken(STIXPatternParser.IdentifierWithoutHyphen, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterKeyPathStep(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitKeyPathStep(this);
		}
	}


}

STIXPatternParser.KeyPathStepContext = KeyPathStepContext;

class SetLiteralContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_setLiteral;
    }

	LPAREN() {
	    return this.getToken(STIXPatternParser.LPAREN, 0);
	};

	RPAREN() {
	    return this.getToken(STIXPatternParser.RPAREN, 0);
	};

	primitiveLiteral = function(i) {
	    if(i===undefined) {
	        i = null;
	    }
	    if(i===null) {
	        return this.getTypedRuleContexts(PrimitiveLiteralContext);
	    } else {
	        return this.getTypedRuleContext(PrimitiveLiteralContext,i);
	    }
	};

	COMMA = function(i) {
		if(i===undefined) {
			i = null;
		}
	    if(i===null) {
	        return this.getTokens(STIXPatternParser.COMMA);
	    } else {
	        return this.getToken(STIXPatternParser.COMMA, i);
	    }
	};


	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterSetLiteral(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitSetLiteral(this);
		}
	}


}



class PrimitiveLiteralContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_primitiveLiteral;
    }

	orderableLiteral() {
	    return this.getTypedRuleContext(OrderableLiteralContext,0);
	};

	BoolLiteral() {
	    return this.getToken(STIXPatternParser.BoolLiteral, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterPrimitiveLiteral(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitPrimitiveLiteral(this);
		}
	}


}



class OrderableLiteralContext extends antlr4.ParserRuleContext {

    constructor(parser, parent, invokingState) {
        if(parent===undefined) {
            parent = null;
        }
        if(invokingState===undefined || invokingState===null) {
            invokingState = -1;
        }
        super(parent, invokingState);
        this.parser = parser;
        this.ruleIndex = STIXPatternParser.RULE_orderableLiteral;
    }

	IntPosLiteral() {
	    return this.getToken(STIXPatternParser.IntPosLiteral, 0);
	};

	IntNegLiteral() {
	    return this.getToken(STIXPatternParser.IntNegLiteral, 0);
	};

	FloatPosLiteral() {
	    return this.getToken(STIXPatternParser.FloatPosLiteral, 0);
	};

	FloatNegLiteral() {
	    return this.getToken(STIXPatternParser.FloatNegLiteral, 0);
	};

	StringLiteral() {
	    return this.getToken(STIXPatternParser.StringLiteral, 0);
	};

	BinaryLiteral() {
	    return this.getToken(STIXPatternParser.BinaryLiteral, 0);
	};

	HexLiteral() {
	    return this.getToken(STIXPatternParser.HexLiteral, 0);
	};

	TimestampLiteral() {
	    return this.getToken(STIXPatternParser.TimestampLiteral, 0);
	};

	enterRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.enterOrderableLiteral(this);
		}
	}

	exitRule(listener) {
	    if(listener instanceof STIXPatternListener ) {
	        listener.exitOrderableLiteral(this);
		}
	}


}




STIXPatternParser.PatternContext = PatternContext; 
STIXPatternParser.ObservationExpressionsContext = ObservationExpressionsContext; 
STIXPatternParser.ObservationExpressionOrContext = ObservationExpressionOrContext; 
STIXPatternParser.ObservationExpressionAndContext = ObservationExpressionAndContext; 
STIXPatternParser.ObservationExpressionContext = ObservationExpressionContext; 
STIXPatternParser.ComparisonExpressionContext = ComparisonExpressionContext; 
STIXPatternParser.ComparisonExpressionAndContext = ComparisonExpressionAndContext; 
STIXPatternParser.PropTestContext = PropTestContext; 
STIXPatternParser.StartStopQualifierContext = StartStopQualifierContext; 
STIXPatternParser.WithinQualifierContext = WithinQualifierContext; 
STIXPatternParser.RepeatedQualifierContext = RepeatedQualifierContext; 
STIXPatternParser.ObjectPathContext = ObjectPathContext; 
STIXPatternParser.ObjectTypeContext = ObjectTypeContext; 
STIXPatternParser.FirstPathComponentContext = FirstPathComponentContext; 
STIXPatternParser.ObjectPathComponentContext = ObjectPathComponentContext; 
STIXPatternParser.SetLiteralContext = SetLiteralContext; 
STIXPatternParser.PrimitiveLiteralContext = PrimitiveLiteralContext; 
STIXPatternParser.OrderableLiteralContext = OrderableLiteralContext; 
